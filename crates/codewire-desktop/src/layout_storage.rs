//! Persistent layout storage for saving/restoring pane layout across restarts.
//!
//! Supports multi-window: each window gets its own layout file under
//! `~/.codewire/windows/{window_id}.json`. A window manifest tracks
//! which windows to restore on startup.

use crate::pane_tree::{PaneId, PaneNode};
use crate::workspace::WorkspaceIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

/// Unique identifier for a window. Generated on first open, persisted for restore.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WindowId(pub String);

impl WindowId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

/// Serialized window position and size
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedBounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Entry in the window manifest — one per window to restore
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindowManifestEntry {
    pub window_id: WindowId,
    pub bounds: Option<SerializedBounds>,
}

/// Manifest of all windows to restore on startup
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindowManifest {
    pub windows: Vec<WindowManifestEntry>,
    /// Which window was last active (for focus on restore)
    pub active_window_id: Option<WindowId>,
}

/// Serializable layout state (per-workspace inner pane tree)
#[derive(Clone, Serialize, Deserialize)]
pub struct LayoutState {
    pub root: PaneNode,
    pub active_pane: PaneId,
}

/// Bump this when the layout format changes incompatibly. A mismatched layout is
/// discarded so removed connection types can never be restored.
const APP_LAYOUT_VERSION: u32 = 3;

/// Full application layout state: outer workspace tree + per-workspace inner layouts
#[derive(Serialize, Deserialize)]
pub struct AppLayoutState {
    /// Schema version — must equal `APP_LAYOUT_VERSION` to be loaded.
    pub version: u32,
    pub outer_tree: PaneNode,
    pub active_outer_pane: PaneId,
    /// Maps workspace_id -> WorkspaceIdentity (for recreating containers)
    pub workspace_identities: HashMap<String, WorkspaceIdentity>,
    /// Maps workspace_id -> inner pane tree
    pub workspace_layouts: HashMap<String, LayoutState>,
}

impl AppLayoutState {
    pub fn new(
        outer_tree: PaneNode,
        active_outer_pane: PaneId,
        workspace_identities: HashMap<String, WorkspaceIdentity>,
        workspace_layouts: HashMap<String, LayoutState>,
    ) -> Self {
        Self {
            version: APP_LAYOUT_VERSION,
            outer_tree,
            active_outer_pane,
            workspace_identities,
            workspace_layouts,
        }
    }
}

/// Handles reading/writing layout JSON to disk.
pub struct LayoutStorage {
    config_dir: PathBuf,
}

impl LayoutStorage {
    /// Create a new LayoutStorage, creating `~/.codewire/` if needed.
    pub fn new() -> Result<Self, io::Error> {
        let home = dirs::home_dir().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Could not determine home directory",
            )
        })?;
        let config_dir = home.join(".codewire");
        std::fs::create_dir_all(&config_dir)?;
        Ok(Self { config_dir })
    }

    /// Load the window manifest. Returns None if missing/corrupt.
    pub fn load_window_manifest(&self) -> Option<WindowManifest> {
        let path = self.config_dir.join("window_manifest.json");
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Save the window manifest.
    pub fn save_window_manifest(&self, manifest: &WindowManifest) -> Result<(), io::Error> {
        let path = self.config_dir.join("window_manifest.json");
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)
    }

    /// Load a specific window's layout by WindowId.
    pub fn load_window_layout(&self, window_id: &WindowId) -> Option<AppLayoutState> {
        let dir = self.config_dir.join("windows");
        let path = dir.join(format!("{}.json", window_id.0));
        let data = std::fs::read_to_string(&path).ok()?;
        let state: AppLayoutState = serde_json::from_str(&data).ok()?;

        if state.version == APP_LAYOUT_VERSION {
            return Some(state);
        }

        let _ = std::fs::remove_file(&path);
        None
    }

    /// Save a specific window's layout.
    pub fn save_window_layout(
        &self,
        window_id: &WindowId,
        state: &AppLayoutState,
    ) -> Result<(), io::Error> {
        let dir = self.config_dir.join("windows");
        std::fs::create_dir_all(&dir)?;
        let versioned = AppLayoutState::new(
            state.outer_tree.clone(),
            state.active_outer_pane,
            state.workspace_identities.clone(),
            state.workspace_layouts.clone(),
        );
        let path = dir.join(format!("{}.json", window_id.0));
        let json = serde_json::to_string_pretty(&versioned)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)
    }

    /// Delete a window's layout file.
    pub fn delete_window_layout(&self, window_id: &WindowId) -> Result<(), io::Error> {
        let dir = self.config_dir.join("windows");
        let path = dir.join(format!("{}.json", window_id.0));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("codewire-desktop-layout-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create test layout directory");
            Self(path)
        }

        fn storage(&self) -> LayoutStorage {
            LayoutStorage {
                config_dir: self.0.clone(),
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn empty_layout() -> AppLayoutState {
        let outer_tree = PaneNode::new_leaf();
        let active_outer_pane = match &outer_tree {
            PaneNode::Leaf(leaf) => leaf.id,
            PaneNode::Split { .. } => unreachable!("new pane tree is a leaf"),
        };
        AppLayoutState::new(
            outer_tree,
            active_outer_pane,
            HashMap::new(),
            HashMap::new(),
        )
    }

    #[test]
    fn current_window_layout_round_trips() {
        let directory = TestDirectory::new();
        let storage = directory.storage();
        let window_id = WindowId::new();

        storage
            .save_window_layout(&window_id, &empty_layout())
            .expect("save current layout");

        assert!(storage.load_window_layout(&window_id).is_some());
    }

    #[test]
    fn previous_window_layout_version_is_rejected() {
        let directory = TestDirectory::new();
        let storage = directory.storage();
        let window_id = WindowId::new();
        let path = directory
            .0
            .join("windows")
            .join(format!("{}.json", window_id.0));
        std::fs::create_dir_all(path.parent().expect("window directory"))
            .expect("create window directory");
        let mut layout = empty_layout();
        layout.version = APP_LAYOUT_VERSION - 1;
        std::fs::write(
            &path,
            serde_json::to_vec(&layout).expect("serialize previous layout"),
        )
        .expect("write previous layout");

        assert!(storage.load_window_layout(&window_id).is_none());
        assert!(!path.exists(), "rejected layout must be discarded");
    }

    #[test]
    fn unversioned_window_layout_is_rejected() {
        let directory = TestDirectory::new();
        let storage = directory.storage();
        let window_id = WindowId::new();
        let path = directory
            .0
            .join("windows")
            .join(format!("{}.json", window_id.0));
        std::fs::create_dir_all(path.parent().expect("window directory"))
            .expect("create window directory");
        let mut layout = serde_json::to_value(empty_layout()).expect("serialize current layout");
        layout
            .as_object_mut()
            .expect("layout object")
            .remove("version");
        std::fs::write(
            &path,
            serde_json::to_vec(&layout).expect("serialize unversioned layout"),
        )
        .expect("write unversioned layout");

        assert!(storage.load_window_layout(&window_id).is_none());
    }
}
