//! Recursive pane tree data structure for VSCode-style split panes.
//!
//! The tree supports free-form splitting: any pane can be split horizontally
//! (side-by-side) or vertically (stacked). Each leaf pane has its own tab bar.

#![allow(dead_code)] // Many methods reserved for future phases (resize, right-click split)

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static PANE_COUNTER: AtomicU64 = AtomicU64::new(1);
static SPLIT_COUNTER: AtomicU64 = AtomicU64::new(1);
static TAB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for a pane
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PaneId(pub u64);

impl PaneId {
    pub fn new() -> Self {
        Self(PANE_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn reset_counter(max_id: u64) {
        PANE_COUNTER.store(max_id + 1, Ordering::Relaxed);
    }
}

/// Unique identifier for a split
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SplitId(pub u64);

impl SplitId {
    pub fn new() -> Self {
        Self(SPLIT_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn reset_counter(max_id: u64) {
        SPLIT_COUNTER.store(max_id + 1, Ordering::Relaxed);
    }
}

/// Unique identifier for a tab
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TabId(pub u64);

impl TabId {
    pub fn new() -> Self {
        Self(TAB_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn reset_counter(max_id: u64) {
        TAB_COUNTER.store(max_id + 1, Ordering::Relaxed);
    }
}

/// Direction of a split
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitDirection {
    /// Panes side-by-side (left | right)
    Horizontal,
    /// Panes stacked (top / bottom)
    Vertical,
}

/// How a remote terminal connects to its target.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoteConnection {
    /// Plain SSH: `ssh <host>`
    Ssh { host: String },
    /// Via Codewire CLI: `cw shell <env>`
    CodewireEnv {
        org_id: String,
        env_id: String,
        env_name: String,
    },
}

/// Content type for a tab
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TabContent {
    /// Terminal connected to a session
    Terminal {
        workspace_id: String,
        session_name: String,
        connection: RemoteConnection,
        session_type: String,
    },
    /// Chat panel
    Chat,
    /// Diff viewer (local folder or SSH)
    Diff {
        source_id: String,
        display_name: String,
        source: crate::local_diff::DiffSource,
    },
    /// File explorer (local folder or SSH)
    Explorer {
        source_id: String,
        display_name: String,
        source: crate::file_browser::FileSource,
    },
    /// File editor
    Editor {
        source_id: String,
        display_name: String,
        source: crate::file_browser::FileSource,
    },
    /// Workspace home landing page
    Home { workspace_id: String },
    /// Workspace container (outer-level tab)
    Workspace {
        workspace_id: String,
        display_name: String,
    },
    /// Internal web browser tab
    WebBrowser { url: String, source_id: String },
}

/// A tab within a pane
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tab {
    pub id: TabId,
    pub title: String,
    pub content: TabContent,
}

impl Tab {
    pub fn new_terminal(
        workspace_id: String,
        session_name: String,
        connection: RemoteConnection,
        session_type: String,
    ) -> Self {
        Self {
            id: TabId::new(),
            title: session_name.clone(),
            content: TabContent::Terminal {
                workspace_id,
                session_name,
                connection,
                session_type,
            },
        }
    }

    pub fn new_chat() -> Self {
        Self {
            id: TabId::new(),
            title: "Chat".to_string(),
            content: TabContent::Chat,
        }
    }

    pub fn new_diff(source: crate::local_diff::DiffSource) -> Self {
        let display_name = source.display_name();
        Self {
            id: TabId::new(),
            title: format!("Diff: {}", display_name),
            content: TabContent::Diff {
                source_id: source.source_id(),
                display_name,
                source,
            },
        }
    }

    pub fn new_explorer(source: crate::file_browser::FileSource) -> Self {
        let display_name = source.display_name();
        Self {
            id: TabId::new(),
            title: display_name.clone(),
            content: TabContent::Explorer {
                source_id: source.source_id(),
                display_name,
                source,
            },
        }
    }

    pub fn new_editor(source: crate::file_browser::FileSource, file_name: String) -> Self {
        Self {
            id: TabId::new(),
            title: file_name,
            content: TabContent::Editor {
                source_id: source.source_id(),
                display_name: source.display_name(),
                source,
            },
        }
    }

    pub fn new_home(workspace_id: String, workspace_name: String) -> Self {
        Self {
            id: TabId::new(),
            title: format!("Home: {}", workspace_name),
            content: TabContent::Home { workspace_id },
        }
    }

    pub fn new_workspace(workspace_id: String, display_name: String) -> Self {
        Self {
            id: TabId::new(),
            title: display_name.clone(),
            content: TabContent::Workspace {
                workspace_id,
                display_name,
            },
        }
    }

    pub fn new_web_browser(url: String, display_name: String) -> Self {
        let source_id = url.clone();
        Self {
            id: TabId::new(),
            title: display_name,
            content: TabContent::WebBrowser { url, source_id },
        }
    }
}

/// A leaf node in the pane tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafPane {
    pub id: PaneId,
    pub tabs: Vec<Tab>,
    pub active_tab: usize,
}

impl LeafPane {
    pub fn new() -> Self {
        Self {
            id: PaneId::new(),
            tabs: Vec::new(),
            active_tab: 0,
        }
    }

    pub fn new_with_tab(tab: Tab) -> Self {
        Self {
            id: PaneId::new(),
            tabs: vec![tab],
            active_tab: 0,
        }
    }

    /// Get the currently active tab
    pub fn active_tab(&self) -> Option<&Tab> {
        self.tabs.get(self.active_tab)
    }

    /// Add a tab to this pane and make it active
    pub fn add_tab(&mut self, tab: Tab) {
        self.tabs.push(tab);
        self.active_tab = self.tabs.len() - 1;
    }

    /// Remove a tab by ID, returns true if removed
    pub fn remove_tab(&mut self, tab_id: TabId) -> bool {
        if let Some(idx) = self.tabs.iter().position(|t| t.id == tab_id) {
            self.tabs.remove(idx);
            // Adjust active_tab if needed
            if self.active_tab >= self.tabs.len() && !self.tabs.is_empty() {
                self.active_tab = self.tabs.len() - 1;
            }
            true
        } else {
            false
        }
    }

    /// Set active tab by ID
    pub fn set_active_tab(&mut self, tab_id: TabId) {
        if let Some(idx) = self.tabs.iter().position(|t| t.id == tab_id) {
            self.active_tab = idx;
        }
    }

    /// Set active tab by index
    pub fn set_active_tab_index(&mut self, index: usize) {
        if index < self.tabs.len() {
            self.active_tab = index;
        }
    }

    /// Find a tab by matching terminal session
    pub fn find_terminal_tab(&self, workspace_id: &str, session_name: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::Terminal {
                workspace_id: ws_id,
                session_name: sess_name,
                ..
            } = &tab.content
            {
                if ws_id == workspace_id && sess_name == session_name {
                    return Some(tab.id);
                }
            }
            None
        })
    }

    pub fn find_diff_tab(&self, source_id: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::Diff { source_id: sid, .. } = &tab.content {
                if sid == source_id {
                    return Some(tab.id);
                }
            }
            None
        })
    }

    pub fn find_explorer_tab(&self, source_id: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::Explorer { source_id: sid, .. } = &tab.content {
                if sid == source_id {
                    return Some(tab.id);
                }
            }
            None
        })
    }

    pub fn find_editor_tab(&self, source_id: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::Editor { source_id: sid, .. } = &tab.content {
                if sid == source_id {
                    return Some(tab.id);
                }
            }
            None
        })
    }

    pub fn find_workspace_tab(&self, workspace_id: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::Workspace {
                workspace_id: wid, ..
            } = &tab.content
            {
                if wid == workspace_id {
                    return Some(tab.id);
                }
            }
            None
        })
    }

    pub fn find_home_tab(&self, workspace_id: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::Home { workspace_id: wid } = &tab.content {
                if wid == workspace_id {
                    return Some(tab.id);
                }
            }
            None
        })
    }

    pub fn find_web_browser_tab(&self, source_id: &str) -> Option<TabId> {
        self.tabs.iter().find_map(|tab| {
            if let TabContent::WebBrowser { source_id: sid, .. } = &tab.content {
                if sid == source_id {
                    return Some(tab.id);
                }
            }
            None
        })
    }
}

/// A node in the pane tree - either a split or a leaf
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PaneNode {
    /// A split containing two children
    Split {
        id: SplitId,
        direction: SplitDirection,
        children: [Box<PaneNode>; 2],
        /// Position of divider (0.0-1.0)
        ratio: f32,
    },
    /// A leaf pane with tabs
    Leaf(LeafPane),
}

impl PaneNode {
    /// Create a new leaf node
    pub fn new_leaf() -> Self {
        PaneNode::Leaf(LeafPane::new())
    }

    /// Create a new leaf node with an initial tab
    pub fn new_leaf_with_tab(tab: Tab) -> Self {
        PaneNode::Leaf(LeafPane::new_with_tab(tab))
    }

    /// Split a pane by its ID
    pub fn split(&mut self, pane_id: PaneId, direction: SplitDirection) -> Option<PaneId> {
        match self {
            PaneNode::Split { children, .. } => {
                // Try both children
                if let Some(new_id) = children[0].split(pane_id, direction) {
                    return Some(new_id);
                }
                children[1].split(pane_id, direction)
            }
            PaneNode::Leaf(leaf) if leaf.id == pane_id => {
                // This is the pane to split
                let new_leaf = LeafPane::new();
                let new_id = new_leaf.id;
                let old_leaf = std::mem::replace(leaf, LeafPane::new());

                *self = PaneNode::Split {
                    id: SplitId::new(),
                    direction,
                    children: [
                        Box::new(PaneNode::Leaf(old_leaf)),
                        Box::new(PaneNode::Leaf(new_leaf)),
                    ],
                    ratio: 0.5,
                };

                Some(new_id)
            }
            PaneNode::Leaf(_) => None,
        }
    }

    /// Close a pane by its ID, returning the remaining tree if any
    pub fn close_pane(&mut self, pane_id: PaneId) -> CloseResult {
        match self {
            PaneNode::Split { children, .. } => {
                // Check first child
                match children[0].close_pane(pane_id) {
                    CloseResult::Removed => {
                        // Replace self with second child
                        *self = *children[1].clone();
                        return CloseResult::Kept;
                    }
                    CloseResult::Kept => return CloseResult::Kept,
                    CloseResult::NotFound => {}
                }

                // Check second child
                match children[1].close_pane(pane_id) {
                    CloseResult::Removed => {
                        // Replace self with first child
                        *self = *children[0].clone();
                        CloseResult::Kept
                    }
                    result => result,
                }
            }
            PaneNode::Leaf(leaf) if leaf.id == pane_id => CloseResult::Removed,
            PaneNode::Leaf(_) => CloseResult::NotFound,
        }
    }

    /// Find a pane by ID
    pub fn find_pane(&self, pane_id: PaneId) -> Option<&LeafPane> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_pane(pane_id)
                .or_else(|| children[1].find_pane(pane_id)),
            PaneNode::Leaf(leaf) if leaf.id == pane_id => Some(leaf),
            PaneNode::Leaf(_) => None,
        }
    }

    /// Find a pane by ID (mutable)
    pub fn find_pane_mut(&mut self, pane_id: PaneId) -> Option<&mut LeafPane> {
        match self {
            PaneNode::Split { children, .. } => {
                // Check first child, then second - can't use or_else due to borrow checker
                if children[0].contains_pane(pane_id) {
                    children[0].find_pane_mut(pane_id)
                } else {
                    children[1].find_pane_mut(pane_id)
                }
            }
            PaneNode::Leaf(leaf) if leaf.id == pane_id => Some(leaf),
            PaneNode::Leaf(_) => None,
        }
    }

    /// Set the split ratio for a pane (finds the split containing this pane)
    pub fn set_ratio(&mut self, pane_id: PaneId, new_ratio: f32) {
        match self {
            PaneNode::Split {
                children, ratio, ..
            } => {
                // Check if either child contains this pane
                if children[0].contains_pane(pane_id) || children[1].contains_pane(pane_id) {
                    *ratio = new_ratio.clamp(0.1, 0.9);
                } else {
                    // Recurse
                    children[0].set_ratio(pane_id, new_ratio);
                    children[1].set_ratio(pane_id, new_ratio);
                }
            }
            PaneNode::Leaf(_) => {}
        }
    }

    /// Set the split ratio by split ID
    pub fn set_ratio_by_split_id(&mut self, split_id: SplitId, new_ratio: f32) {
        match self {
            PaneNode::Split {
                id,
                children,
                ratio,
                ..
            } => {
                if *id == split_id {
                    *ratio = new_ratio.clamp(0.1, 0.9);
                } else {
                    // Recurse
                    children[0].set_ratio_by_split_id(split_id, new_ratio);
                    children[1].set_ratio_by_split_id(split_id, new_ratio);
                }
            }
            PaneNode::Leaf(_) => {}
        }
    }

    /// Check if this node contains a pane with the given ID
    pub fn contains_pane(&self, pane_id: PaneId) -> bool {
        match self {
            PaneNode::Split { children, .. } => {
                children[0].contains_pane(pane_id) || children[1].contains_pane(pane_id)
            }
            PaneNode::Leaf(leaf) => leaf.id == pane_id,
        }
    }

    /// Get the first leaf pane (for default active pane)
    pub fn first_leaf(&self) -> &LeafPane {
        match self {
            PaneNode::Split { children, .. } => children[0].first_leaf(),
            PaneNode::Leaf(leaf) => leaf,
        }
    }

    /// Get the first leaf pane (mutable)
    pub fn first_leaf_mut(&mut self) -> &mut LeafPane {
        match self {
            PaneNode::Split { children, .. } => children[0].first_leaf_mut(),
            PaneNode::Leaf(leaf) => leaf,
        }
    }

    /// Find a tab across all panes by matching terminal session
    pub fn find_terminal_tab(
        &self,
        workspace_id: &str,
        session_name: &str,
    ) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_terminal_tab(workspace_id, session_name)
                .or_else(|| children[1].find_terminal_tab(workspace_id, session_name)),
            PaneNode::Leaf(leaf) => leaf
                .find_terminal_tab(workspace_id, session_name)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Find a diff tab by source ID
    pub fn find_diff_tab(&self, source_id: &str) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_diff_tab(source_id)
                .or_else(|| children[1].find_diff_tab(source_id)),
            PaneNode::Leaf(leaf) => leaf
                .find_diff_tab(source_id)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Find an explorer tab by source ID
    pub fn find_explorer_tab(&self, source_id: &str) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_explorer_tab(source_id)
                .or_else(|| children[1].find_explorer_tab(source_id)),
            PaneNode::Leaf(leaf) => leaf
                .find_explorer_tab(source_id)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Find an editor tab by source ID
    pub fn find_editor_tab(&self, source_id: &str) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_editor_tab(source_id)
                .or_else(|| children[1].find_editor_tab(source_id)),
            PaneNode::Leaf(leaf) => leaf
                .find_editor_tab(source_id)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Find a workspace tab by workspace ID
    pub fn find_workspace_tab(&self, workspace_id: &str) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_workspace_tab(workspace_id)
                .or_else(|| children[1].find_workspace_tab(workspace_id)),
            PaneNode::Leaf(leaf) => leaf
                .find_workspace_tab(workspace_id)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Find a home tab by workspace ID
    pub fn find_home_tab(&self, workspace_id: &str) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_home_tab(workspace_id)
                .or_else(|| children[1].find_home_tab(workspace_id)),
            PaneNode::Leaf(leaf) => leaf
                .find_home_tab(workspace_id)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Find a web browser tab by source ID
    pub fn find_web_browser_tab(&self, source_id: &str) -> Option<(PaneId, TabId)> {
        match self {
            PaneNode::Split { children, .. } => children[0]
                .find_web_browser_tab(source_id)
                .or_else(|| children[1].find_web_browser_tab(source_id)),
            PaneNode::Leaf(leaf) => leaf
                .find_web_browser_tab(source_id)
                .map(|tab_id| (leaf.id, tab_id)),
        }
    }

    /// Collect all pane IDs in the tree
    pub fn all_pane_ids(&self) -> Vec<PaneId> {
        match self {
            PaneNode::Split { children, .. } => {
                let mut ids = children[0].all_pane_ids();
                ids.extend(children[1].all_pane_ids());
                ids
            }
            PaneNode::Leaf(leaf) => vec![leaf.id],
        }
    }

    /// Remove tabs matching a predicate from all leaf panes.
    pub fn remove_tabs_by<F: Fn(&Tab) -> bool>(&mut self, predicate: &F) {
        match self {
            PaneNode::Leaf(leaf) => leaf.tabs.retain(|t| !predicate(t)),
            PaneNode::Split { children, .. } => {
                children[0].remove_tabs_by(predicate);
                children[1].remove_tabs_by(predicate);
            }
        }
    }

    /// Traverse the tree and return (max_pane_id, max_split_id, max_tab_id)
    pub fn max_ids(&self) -> (u64, u64, u64) {
        match self {
            PaneNode::Split { id, children, .. } => {
                let (p0, s0, t0) = children[0].max_ids();
                let (p1, s1, t1) = children[1].max_ids();
                (p0.max(p1), id.0.max(s0).max(s1), t0.max(t1))
            }
            PaneNode::Leaf(leaf) => {
                let max_tab = leaf.tabs.iter().map(|t| t.id.0).max().unwrap_or(0);
                (leaf.id.0, 0, max_tab)
            }
        }
    }
}

/// Result of closing a pane
pub enum CloseResult {
    /// Pane was found and removed (caller should replace with sibling)
    Removed,
    /// Pane was found and tree was restructured
    Kept,
    /// Pane was not found
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_leaf() {
        let node = PaneNode::new_leaf();
        if let PaneNode::Leaf(leaf) = node {
            assert!(leaf.tabs.is_empty());
            assert_eq!(leaf.active_tab, 0);
        } else {
            panic!("Expected Leaf node");
        }
    }

    #[test]
    fn test_add_tab() {
        let mut leaf = LeafPane::new();
        let tab1 = Tab::new_chat();
        let tab2 = Tab::new_chat();

        leaf.add_tab(tab1);
        assert_eq!(leaf.tabs.len(), 1);
        assert_eq!(leaf.active_tab, 0);

        leaf.add_tab(tab2);
        assert_eq!(leaf.tabs.len(), 2);
        assert_eq!(leaf.active_tab, 1); // New tab becomes active
    }

    #[test]
    fn test_split_horizontal() {
        let mut root = PaneNode::new_leaf();
        let original_id = if let PaneNode::Leaf(leaf) = &root {
            leaf.id
        } else {
            panic!("Expected Leaf");
        };

        let new_id = root.split(original_id, SplitDirection::Horizontal);
        assert!(new_id.is_some());

        if let PaneNode::Split {
            direction,
            children,
            ratio,
            ..
        } = &root
        {
            assert_eq!(*direction, SplitDirection::Horizontal);
            assert_eq!(*ratio, 0.5);
            assert!(matches!(children[0].as_ref(), PaneNode::Leaf(_)));
            assert!(matches!(children[1].as_ref(), PaneNode::Leaf(_)));
        } else {
            panic!("Expected Split node after split");
        }
    }

    #[test]
    fn test_close_pane() {
        let mut root = PaneNode::new_leaf();
        let first_id = if let PaneNode::Leaf(leaf) = &root {
            leaf.id
        } else {
            panic!("Expected Leaf");
        };

        // Split it
        let second_id = root.split(first_id, SplitDirection::Horizontal).unwrap();

        // Close the second pane
        let result = root.close_pane(second_id);
        assert!(matches!(result, CloseResult::Kept));

        // Should be back to a single leaf
        assert!(matches!(root, PaneNode::Leaf(_)));
    }

    #[test]
    fn test_find_terminal_tab() {
        let mut leaf = LeafPane::new();
        leaf.add_tab(Tab::new_terminal(
            "ws1".to_string(),
            "session1".to_string(),
            RemoteConnection::Ssh {
                host: "env.ws1".to_string(),
            },
            "zellij".to_string(),
        ));
        leaf.add_tab(Tab::new_terminal(
            "ws2".to_string(),
            "session2".to_string(),
            RemoteConnection::Ssh {
                host: "env.ws2".to_string(),
            },
            "tmux".to_string(),
        ));

        let found = leaf.find_terminal_tab("ws1", "session1");
        assert!(found.is_some());

        let not_found = leaf.find_terminal_tab("ws3", "session3");
        assert!(not_found.is_none());
    }
}
