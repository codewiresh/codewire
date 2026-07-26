//! Centralized workspace routing layer.
//!
//! Consolidates the pattern of: construct identity → open workspace → open tab
//! into a single `OpenWorkspaceRequest` event and `route_workspace()` dispatch.

use crate::workspace::{WorkspaceIdentity, WorkspaceSource};

/// What tab to open after resolving the workspace container.
#[derive(Clone, Debug)]
pub enum TabAction {
    /// Switch to the workspace without opening a tab.
    None,
    /// Open a named terminal session (e.g. clicking an existing tmux/zellij session).
    Terminal {
        session_name: String,
        ssh_host: String,
        session_type: String,
    },
    /// Open a new auto-named terminal (remote SSH or local shell).
    NewTerminal,
    /// Open a file explorer.
    Explorer,
    /// Open a diff view.
    Diff,
    /// Open both explorer and diff (used when opening a local folder for the first time).
    ExplorerAndDiff,
}

/// Unified event replacing 7 sidebar event structs.
///
/// Emitted by `Sidebar` and handled by `AppView::on_open_workspace_request`,
/// which delegates to `route_workspace()`.
#[derive(Clone, Debug)]
pub struct OpenWorkspaceRequest {
    pub identity: WorkspaceIdentity,
    pub action: TabAction,
}

impl OpenWorkspaceRequest {
    /// Click on an existing remote terminal session.
    pub fn remote_terminal(
        provider_id: String,
        workspace_id: String,
        workspace_name: String,
        ssh_host: String,
        session_name: String,
        session_type: String,
    ) -> Self {
        Self {
            identity: WorkspaceIdentity::remote(
                provider_id,
                workspace_id,
                workspace_name,
                ssh_host.clone(),
            ),
            action: TabAction::Terminal {
                session_name,
                ssh_host,
                session_type,
            },
        }
    }

    /// "View Diff" on a remote workspace.
    pub fn remote_diff(
        provider_id: String,
        workspace_id: String,
        workspace_name: String,
        ssh_host: String,
    ) -> Self {
        Self {
            identity: WorkspaceIdentity::remote(
                provider_id,
                workspace_id,
                workspace_name,
                ssh_host,
            ),
            action: TabAction::Diff,
        }
    }

    /// "Browse Files" on a remote workspace.
    pub fn remote_browse(
        provider_id: String,
        workspace_id: String,
        workspace_name: String,
        ssh_host: String,
    ) -> Self {
        Self {
            identity: WorkspaceIdentity::remote(
                provider_id,
                workspace_id,
                workspace_name,
                ssh_host,
            ),
            action: TabAction::Explorer,
        }
    }

    /// "New Terminal" on a remote workspace.
    pub fn remote_new_terminal(
        provider_id: String,
        workspace_id: String,
        workspace_name: String,
        ssh_host: String,
    ) -> Self {
        Self {
            identity: WorkspaceIdentity::remote(
                provider_id,
                workspace_id,
                workspace_name,
                ssh_host,
            ),
            action: TabAction::NewTerminal,
        }
    }

    /// "Browse Files" on a local project.
    pub fn local_browse(path: String) -> Self {
        Self {
            identity: WorkspaceIdentity::local(path),
            action: TabAction::Explorer,
        }
    }

    /// "View Diff" on a local project.
    pub fn local_diff(path: String) -> Self {
        Self {
            identity: WorkspaceIdentity::local(path),
            action: TabAction::Diff,
        }
    }

    /// "New Terminal" on a local project.
    pub fn local_new_terminal(path: String) -> Self {
        Self {
            identity: WorkspaceIdentity::local(path),
            action: TabAction::NewTerminal,
        }
    }

    /// Open a local folder for the first time (explorer + diff).
    pub fn local_folder_opened(path: String) -> Self {
        Self {
            identity: WorkspaceIdentity::local(path),
            action: TabAction::ExplorerAndDiff,
        }
    }

    /// Click on a workspace row to switch to it (no tab opened).
    pub fn activate(identity: WorkspaceIdentity) -> Self {
        Self {
            identity,
            action: TabAction::None,
        }
    }
}

/// Derive a `FileSource` from a `WorkspaceSource`.
pub fn file_source_for(source: &WorkspaceSource) -> crate::file_browser::FileSource {
    match source {
        WorkspaceSource::Local { path } => crate::file_browser::FileSource::Local {
            root_path: path.clone(),
        },
        WorkspaceSource::Remote { ssh_host, .. } => crate::file_browser::FileSource::Ssh {
            ssh_host: ssh_host.clone(),
            root_path: "/workspace".to_string(),
        },
    }
}

/// Derive a `DiffSource` from a `WorkspaceSource`.
pub fn diff_source_for(source: &WorkspaceSource) -> crate::local_diff::DiffSource {
    match source {
        WorkspaceSource::Local { path } => crate::local_diff::DiffSource::Local {
            path: path.clone(),
        },
        WorkspaceSource::Remote {
            ssh_host,
            workspace_id: _,
            provider_id: _,
        } => {
            // For SSH diff, we need the workspace name. Since WorkspaceSource
            // doesn't carry it, so strip the environment host prefix when present.
            let workspace_name = ssh_host
                .strip_prefix("env.")
                .unwrap_or(ssh_host)
                .to_string();
            crate::local_diff::DiffSource::Ssh {
                workspace_name,
                ssh_host: ssh_host.clone(),
            }
        }
    }
}
