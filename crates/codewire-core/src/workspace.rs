//! Workspace management (native only — uses tokio::sync::RwLock)

use crate::CoreError;
use crate::types::{RuntimeType, Workspace, WorkspaceStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages workspaces
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct WorkspaceManager {
    workspaces: Arc<RwLock<HashMap<String, Workspace>>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl WorkspaceManager {
    /// Create a new workspace manager
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Self {
        Self {
            workspaces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// List all workspaces
    pub async fn list_workspaces(&self) -> Vec<Workspace> {
        let workspaces = self.workspaces.read().await;
        workspaces.values().cloned().collect()
    }

    /// Get a workspace by ID
    pub async fn get_workspace(&self, id: String) -> Result<Workspace, CoreError> {
        let workspaces = self.workspaces.read().await;
        workspaces
            .get(&id)
            .cloned()
            .ok_or(CoreError::WorkspaceNotFound { id })
    }

    /// Create a new local workspace
    pub async fn create_local_workspace(
        &self,
        name: String,
        project_path: String,
    ) -> Result<Workspace, CoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        let workspace = Workspace {
            id: id.clone(),
            name,
            project_path,
            runtime_type: RuntimeType::Local,
            status: WorkspaceStatus::Ready,
        };

        let mut workspaces = self.workspaces.write().await;
        workspaces.insert(id, workspace.clone());
        Ok(workspace)
    }

    /// Create a new SSH workspace
    pub async fn create_ssh_workspace(
        &self,
        name: String,
        host: String,
        user: String,
        project_path: String,
    ) -> Result<Workspace, CoreError> {
        let id = uuid::Uuid::new_v4().to_string();
        let workspace = Workspace {
            id: id.clone(),
            name,
            project_path,
            runtime_type: RuntimeType::Ssh { host, user },
            status: WorkspaceStatus::Connecting,
        };

        let mut workspaces = self.workspaces.write().await;
        workspaces.insert(id, workspace.clone());
        Ok(workspace)
    }

    /// Update workspace status
    pub async fn update_status(
        &self,
        id: String,
        status: WorkspaceStatus,
    ) -> Result<(), CoreError> {
        let mut workspaces = self.workspaces.write().await;
        let workspace = workspaces
            .get_mut(&id)
            .ok_or(CoreError::WorkspaceNotFound { id })?;
        workspace.status = status;
        Ok(())
    }

    /// Remove a workspace
    pub async fn remove_workspace(&self, id: String) -> Result<(), CoreError> {
        let mut workspaces = self.workspaces.write().await;
        workspaces
            .remove(&id)
            .ok_or(CoreError::WorkspaceNotFound { id })?;
        Ok(())
    }
}

impl Default for WorkspaceManager {
    fn default() -> Self {
        Self::new()
    }
}
