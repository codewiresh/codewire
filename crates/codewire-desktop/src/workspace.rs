//! Workspace identity types for local workspaces and Codewire surfaces.

use serde::{Deserialize, Serialize};

/// The source of a workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkspaceSource {
    /// A local folder on disk.
    Local { path: String },
    /// The shared dashboard/browser host for Codewire web routes.
    Dashboard,
    /// A Codewire environment terminal workspace.
    CodewireEnvironment {
        org_id: String,
        org_slug: String,
        env_id: String,
    },
}

/// Identity for a workspace container.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceIdentity {
    /// Unique ID: `local:/path`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Source details.
    pub source: WorkspaceSource,
}

impl WorkspaceIdentity {
    /// Create identity for a local folder workspace.
    pub fn local(path: String) -> Self {
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        Self {
            id: format!("local:{}", path),
            name,
            source: WorkspaceSource::Local { path },
        }
    }

    /// Create identity for the shared Codewire dashboard workspace.
    pub fn dashboard() -> Self {
        Self {
            id: "codewire:dashboard".to_string(),
            name: "Dashboard".to_string(),
            source: WorkspaceSource::Dashboard,
        }
    }

    /// Create identity for a Codewire environment workspace.
    pub fn codewire_environment(
        org_id: String,
        org_slug: String,
        env_id: String,
        env_name: String,
    ) -> Self {
        Self {
            id: format!("codewire:env:{}:{}", org_id, env_id),
            name: env_name,
            source: WorkspaceSource::CodewireEnvironment {
                org_id,
                org_slug,
                env_id,
            },
        }
    }
}
