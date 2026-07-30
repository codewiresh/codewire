//! Workspace identity and presentation types for local and Codewire surfaces.

use serde::{Deserialize, Serialize};

/// Wire-independent port data rendered by the retained native environment UI.
#[derive(Clone, Debug)]
pub struct EnvironmentPortSummary {
    pub port: i32,
    pub label: String,
    pub access: String,
    pub preview_url: Option<String>,
}

/// Wire-independent environment data rendered by the retained native UI.
///
/// Connect messages are converted at the application boundary. Persisted
/// window layout therefore never becomes a second protocol implementation.
#[derive(Clone, Debug)]
pub struct EnvironmentSummary {
    pub id: String,
    pub name: String,
    pub state: String,
    pub desired_state: String,
    pub error_reason: String,
    pub setup_error: String,
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
    pub total_running_seconds: i32,
    pub protected: bool,
    pub preset_name: String,
    pub network: String,
    pub ports: Vec<EnvironmentPortSummary>,
}

/// The source of a workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkspaceSource {
    /// A local folder on disk.
    Local { path: String },
    /// The native Codewire landing surface.
    Dashboard,
    /// A Codewire environment workspace backed by typed Connect reads.
    CodewireEnvironment {
        org_id: String,
        org_slug: String,
        env_id: String,
        #[serde(default)]
        env_name: String,
        /// Live Connect data is never persisted in the window layout.
        #[serde(skip)]
        environment: Option<EnvironmentSummary>,
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
        environment: EnvironmentSummary,
    ) -> Self {
        Self {
            id: format!("codewire:env:{}:{}", org_id, environment.id),
            name: environment.name.clone(),
            source: WorkspaceSource::CodewireEnvironment {
                org_id,
                org_slug,
                env_id: environment.id.clone(),
                env_name: environment.name.clone(),
                environment: Some(environment),
            },
        }
    }
}
