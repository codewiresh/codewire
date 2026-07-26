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

/// Bump this when the layout format changes in a way that's incompatible with
/// previously saved layouts.  `load_app_layout` silently discards any file whose
/// version doesn't match, so the app starts fresh instead of restoring stale data.
const APP_LAYOUT_VERSION: u32 = 2;

/// Full application layout state: outer workspace tree + per-workspace inner layouts
#[derive(Serialize, Deserialize)]
pub struct AppLayoutState {
    /// Schema version — must equal `APP_LAYOUT_VERSION` to be loaded.
    #[serde(default)]
    pub version: u32,
    pub outer_tree: PaneNode,
    pub active_outer_pane: PaneId,
    /// Maps workspace_id -> WorkspaceIdentity (for recreating containers)
    pub workspace_identities: HashMap<String, WorkspaceIdentity>,
    /// Maps workspace_id -> inner pane tree
    pub workspace_layouts: HashMap<String, LayoutState>,
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

    /// Load layout from disk. Returns `None` on missing or corrupt file (self-healing).
    pub fn load(&self) -> Option<LayoutState> {
        let path = self.config_dir.join("layout.json");
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Save layout to disk as pretty-printed JSON.
    pub fn save(&self, state: &LayoutState) -> Result<(), io::Error> {
        let path = self.config_dir.join("layout.json");
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)
    }

    // --- Legacy single-file methods (used for migration and single-window compat) ---

    /// Load full application layout from legacy `app_layout.json`.
    /// Returns `None` if the file is missing or corrupt.
    pub fn load_app_layout(&self) -> Option<AppLayoutState> {
        let path = self.config_dir.join("app_layout.json");
        let data = std::fs::read_to_string(&path).ok()?;
        let mut state: AppLayoutState = serde_json::from_str(&data).ok()?;

        if state.version == APP_LAYOUT_VERSION {
            return Some(state);
        }

        // Migration: v0 (no version field) -> v2
        if state.version == 0 {
            tracing::info!("Migrating saved layout from v0 -> v{}", APP_LAYOUT_VERSION);
            state.version = APP_LAYOUT_VERSION;
            return Some(state);
        }

        tracing::info!(
            "Discarding saved layout (version {} != current {})",
            state.version,
            APP_LAYOUT_VERSION
        );
        let _ = std::fs::remove_file(&path);
        None
    }

    /// Save full application layout to legacy `app_layout.json`.
    pub fn save_app_layout(&self, state: &AppLayoutState) -> Result<(), io::Error> {
        let versioned = AppLayoutState {
            version: APP_LAYOUT_VERSION,
            outer_tree: state.outer_tree.clone(),
            active_outer_pane: state.active_outer_pane,
            workspace_identities: state.workspace_identities.clone(),
            workspace_layouts: state.workspace_layouts.clone(),
        };
        let path = self.config_dir.join("app_layout.json");
        let json = serde_json::to_string_pretty(&versioned)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)
    }

    // --- Multi-window methods ---

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
        let mut state: AppLayoutState = serde_json::from_str(&data).ok()?;

        if state.version == APP_LAYOUT_VERSION {
            return Some(state);
        }

        if state.version == 0 {
            state.version = APP_LAYOUT_VERSION;
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
        let versioned = AppLayoutState {
            version: APP_LAYOUT_VERSION,
            outer_tree: state.outer_tree.clone(),
            active_outer_pane: state.active_outer_pane,
            workspace_identities: state.workspace_identities.clone(),
            workspace_layouts: state.workspace_layouts.clone(),
        };
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

    /// Migrate from legacy single-file `app_layout.json` to multi-window storage.
    /// Returns the WindowId assigned to the migrated layout if migration occurred.
    pub fn migrate_to_multi_window(&self) -> Option<(WindowId, AppLayoutState)> {
        let legacy = self.load_app_layout()?;
        let window_id = WindowId::new();

        // Save as per-window layout
        if let Err(e) = self.save_window_layout(&window_id, &legacy) {
            tracing::warn!("Failed to save migrated window layout: {}", e);
            return None;
        }

        // Save manifest with single window
        let manifest = WindowManifest {
            windows: vec![WindowManifestEntry {
                window_id: window_id.clone(),
                bounds: None,
            }],
            active_window_id: Some(window_id.clone()),
        };
        if let Err(e) = self.save_window_manifest(&manifest) {
            tracing::warn!("Failed to save window manifest: {}", e);
        }

        // Remove legacy file
        let legacy_path = self.config_dir.join("app_layout.json");
        let _ = std::fs::remove_file(&legacy_path);

        tracing::info!(
            "Migrated legacy app_layout.json -> windows/{}.json",
            window_id.0
        );
        Some((window_id, legacy))
    }
}
