//! Split container that renders the recursive pane tree.
//!
//! This component owns the pane tree and all terminal entities,
//! handling tab/pane events and rendering the tree recursively.

#![allow(dead_code)] // Methods reserved for future phases (resize, right-click split)

use crate::chat::ChatPanel;
use crate::diff_view::DiffView;
use crate::file_browser::{FileExplorer, FileSelected, FileSource};
use crate::layout_storage::LayoutState;
use crate::pane_tree::{
    CloseResult, LeafPane, PaneId, PaneNode, SplitDirection, SplitId, Tab, TabContent, TabId,
    TerminalConnection,
};
use crate::terminal::TerminalView;
use crate::theme::Theme;
use crate::web_browser::WebBrowserView;
use crate::workspace_home::WorkspaceHome;
use codewire_ui::icon_button;
use gpui::{
    App, Bounds, Context, ElementId, Entity, EventEmitter, FocusHandle, Focusable, MouseButton,
    MouseDownEvent, MouseMoveEvent, Pixels, Point, SharedString, Window, anchored, div, prelude::*,
    px, svg,
};
use std::collections::HashMap;

/// Data transferred when dragging a tab
#[derive(Clone, Debug)]
pub struct TabDragData {
    /// The pane the tab is being dragged from
    pub source_pane_id: PaneId,
    /// The tab being dragged
    pub tab: Tab,
}

/// Visual preview shown while dragging a tab
struct TabDragPreview {
    title: String,
}

impl Render for TabDragPreview {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();
        div()
            .px_3()
            .py_1()
            .bg(theme.surface)
            .border_1()
            .border_color(theme.accent)
            .rounded(px(4.0))
            .text_size(px(12.0))
            .text_color(theme.foreground)
            .child(self.title.clone())
    }
}

/// Event emitted when a tab is closed and pane becomes empty
#[derive(Clone, Debug)]
pub struct PaneEmpty {
    pub pane_id: PaneId,
}

/// Event emitted when the active pane changes
#[derive(Clone, Debug)]
pub struct ActivePaneChanged {
    pub pane_id: PaneId,
}

/// State for tracking an active divider drag
#[derive(Clone, Copy, Debug)]
struct DividerDrag {
    split_id: SplitId,
    direction: SplitDirection,
    /// Starting mouse position (in pixels)
    start_position: f32,
    /// Starting ratio when drag began
    start_ratio: f32,
    /// Container size (for calculating ratio delta)
    container_size: f32,
}

/// State for tracking an active sidebar resize drag
#[derive(Clone, Copy, Debug)]
struct SidebarDrag {
    /// Starting mouse X position (in pixels)
    start_x: f32,
    /// Starting sidebar width when drag began
    start_width: f32,
}

/// State for the unsaved changes confirmation dialog
#[derive(Clone, Debug)]
struct UnsavedChangesDialog {
    pane_id: PaneId,
    tab_id: TabId,
    source_id: String,
    file_name: String,
}

/// Context menu state for inner tabs
#[derive(Clone, Debug)]
struct InnerContextMenu {
    position: Point<Pixels>,
    pane_id: PaneId,
    tab_id: TabId,
    tab_index: usize,
    tab_count: usize,
}

/// Split container that manages the pane tree for a single workspace.
pub struct SplitContainer {
    /// ID of the workspace this container belongs to (empty string for default)
    workspace_id: String,
    /// Identity of the workspace (None for the default container)
    workspace_identity: Option<crate::workspace::WorkspaceIdentity>,
    /// The root of the pane tree
    root: PaneNode,
    /// Currently active pane ID
    active_pane: PaneId,
    /// Terminal entities keyed by (workspace_id, session_name)
    terminals: HashMap<(String, String), Entity<TerminalView>>,
    /// Diff view entities keyed by source_id
    diff_views: HashMap<String, Entity<DiffView>>,
    /// File explorer entities keyed by source_id
    explorers: HashMap<String, Entity<FileExplorer>>,
    /// Editor view entities keyed by source_id
    editor_views: HashMap<String, Entity<crate::editor::EditorView>>,
    /// Home view entities keyed by workspace_id
    home_views: HashMap<String, Entity<WorkspaceHome>>,
    /// Web browser view entities keyed by source_id (URL)
    web_browsers: HashMap<String, Entity<WebBrowserView>>,
    /// Shared chat panel entity (reference, not owned)
    chat_panel: Entity<ChatPanel>,
    /// Active divider drag state
    divider_drag: Option<DividerDrag>,
    /// Explorer sidebar visibility
    explorer_sidebar_visible: bool,
    /// Explorer sidebar width in pixels (clamped 150–500)
    explorer_sidebar_width: f32,
    /// Explorer sidebar file source (set when workspace identity is known)
    explorer_sidebar_source: Option<FileSource>,
    /// Active sidebar resize drag state
    sidebar_drag: Option<SidebarDrag>,
    /// Right-click context menu for inner tabs
    context_menu: Option<InnerContextMenu>,
    /// Unsaved changes confirmation dialog
    unsaved_dialog: Option<UnsavedChangesDialog>,
    /// Measured container sizes for each split node (for accurate drag calculations)
    split_sizes: HashMap<SplitId, f32>,
    focus_handle: FocusHandle,
}

impl EventEmitter<PaneEmpty> for SplitContainer {}
impl EventEmitter<ActivePaneChanged> for SplitContainer {}

impl SplitContainer {
    pub fn new(chat_panel: Entity<ChatPanel>, cx: &mut Context<Self>) -> Self {
        // AppLayout applies a validated current pane tree after construction
        // when restoring a window.
        let initial_pane = LeafPane::new_with_tab(Tab::new_chat());
        let active_pane = initial_pane.id;
        let root = PaneNode::Leaf(initial_pane);

        Self {
            workspace_id: String::new(),
            workspace_identity: None,
            root,
            active_pane,
            terminals: HashMap::new(),
            diff_views: HashMap::new(),
            explorers: HashMap::new(),
            editor_views: HashMap::new(),
            home_views: HashMap::new(),
            web_browsers: HashMap::new(),
            chat_panel,
            divider_drag: None,
            explorer_sidebar_visible: false,
            explorer_sidebar_width: 240.0,
            explorer_sidebar_source: None,
            sidebar_drag: None,
            context_menu: None,
            unsaved_dialog: None,
            split_sizes: HashMap::new(),
            focus_handle: cx.focus_handle(),
        }
    }

    /// Set the workspace identity (used when restoring from saved layout).
    pub fn set_workspace_identity(&mut self, identity: crate::workspace::WorkspaceIdentity) {
        self.workspace_id = identity.id.clone();
        self.workspace_identity = Some(identity);
    }

    /// Get the workspace identity.
    pub fn workspace_identity(&self) -> Option<&crate::workspace::WorkspaceIdentity> {
        self.workspace_identity.as_ref()
    }

    /// Restore a saved pane tree layout.
    pub fn restore_layout(&mut self, root: PaneNode, active_pane: PaneId) {
        self.root = root;
        self.active_pane = active_pane;
    }

    /// Get a reference to the root pane node (for computing max IDs during restore).
    pub fn root_node(&self) -> &PaneNode {
        &self.root
    }

    /// Get the current layout state for persistence.
    pub fn layout_state(&self) -> LayoutState {
        LayoutState {
            root: self.root.clone(),
            active_pane: self.active_pane,
        }
    }

    /// Number of terminal entities currently tracked.
    pub fn terminal_count(&self) -> usize {
        self.terminals.len()
    }

    /// Get the currently active pane
    pub fn active_pane(&self) -> Option<&LeafPane> {
        self.root.find_pane(self.active_pane)
    }

    /// Get the currently active pane (mutable)
    pub fn active_pane_mut(&mut self) -> Option<&mut LeafPane> {
        self.root.find_pane_mut(self.active_pane)
    }

    /// Open a home tab for a workspace.
    pub fn open_home(
        &mut self,
        identity: crate::workspace::WorkspaceIdentity,
        cx: &mut Context<Self>,
    ) {
        let workspace_id = identity.id.clone();

        // Check if home tab already exists
        if let Some((pane_id, tab_id)) = self.root.find_home_tab(&workspace_id) {
            self.active_pane = pane_id;
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            cx.notify();
            return;
        }

        // Create home view entity
        if !self.home_views.contains_key(&workspace_id) {
            let id = identity.clone();
            let home = cx.new(|cx| WorkspaceHome::new(id, cx));
            self.home_views.insert(workspace_id.clone(), home);
        }

        let tab = Tab::new_home(workspace_id, identity.name);
        if let Some(pane) = self.active_pane_mut() {
            pane.add_tab(tab);
        }

        cx.notify();
    }

    /// Get all home view workspace IDs.
    pub fn home_workspace_ids(&self) -> Vec<String> {
        self.home_views.keys().cloned().collect()
    }

    /// Open a web browser tab for the given URL.
    ///
    /// If a tab with the same URL already exists, switches to it.
    pub fn open_web_browser(
        &mut self,
        url: String,
        provider_url: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let source_id = url.clone();

        // Check if web browser tab already exists anywhere
        if let Some((pane_id, tab_id)) = self.root.find_web_browser_tab(&source_id) {
            self.active_pane = pane_id;
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            // Show the webview (it may have been hidden)
            if let Some(browser) = self.web_browsers.get(&source_id) {
                browser.update(cx, |b, cx| b.set_visible(true, cx));
            }
            cx.notify();
            return;
        }

        // Create new web browser entity
        if !self.web_browsers.contains_key(&source_id) {
            let u = url.clone();
            let pu = provider_url.clone();
            let browser = cx.new(|cx| WebBrowserView::new(u, pu, cx));
            self.web_browsers.insert(source_id.clone(), browser);
        }

        // Derive a display name from the URL
        let display_name = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(&url)
            .split('/')
            .filter(|s| !s.is_empty())
            .last()
            .unwrap_or("Browser")
            .to_string();

        let tab = Tab::new_web_browser(url, display_name);
        if let Some(pane) = self.active_pane_mut() {
            pane.add_tab(tab);
        }

        cx.notify();
    }

    /// Open a terminal tab for a session
    ///
    /// If the tab already exists, switches to it. Otherwise creates a new tab
    /// in the active pane.
    pub fn open_terminal(
        &mut self,
        workspace_id: String,
        session_name: String,
        connection: TerminalConnection,
        session_type: String,
        cx: &mut Context<Self>,
    ) {
        // Check if tab already exists anywhere
        if let Some((pane_id, tab_id)) = self.root.find_terminal_tab(&workspace_id, &session_name) {
            // Switch to existing tab
            self.active_pane = pane_id;
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            cx.notify();
            return;
        }

        // Create new terminal entity if needed
        let key = (workspace_id.clone(), session_name.clone());
        if !self.terminals.contains_key(&key) {
            let terminal = cx.new(|cx| TerminalView::new(cx));
            terminal.update(cx, |t, cx| {
                Self::connect_terminal(t, &connection, cx);
            });
            self.terminals.insert(key.clone(), terminal);
        }

        // Add tab to active pane
        let tab = Tab::new_terminal(workspace_id, session_name, connection, session_type);
        if let Some(pane) = self.active_pane_mut() {
            pane.add_tab(tab);
        }

        cx.notify();
    }

    /// Open a local terminal tab.
    pub fn open_local_terminal(&mut self, cx: &mut Context<Self>) {
        let n = self.terminals.len() + 1;
        let session_name = format!("local-{}", n);
        let workspace_id = "local".to_string();

        let terminal = cx.new(|cx| TerminalView::new(cx));
        terminal.update(cx, |t, cx| {
            t.connect_local(cx);
        });

        let key = (workspace_id.clone(), session_name.clone());
        self.terminals.insert(key, terminal);

        let tab = Tab::new_terminal(
            workspace_id,
            session_name,
            TerminalConnection::Local,
            "local".to_string(),
        );
        if let Some(pane) = self.active_pane_mut() {
            pane.add_tab(tab);
        }
        cx.notify();
    }

    /// Open a diff view tab for a local folder.
    ///
    /// If the tab already exists, switches to it. Otherwise creates a new tab.
    pub fn open_diff(&mut self, source: crate::local_diff::DiffSource, cx: &mut Context<Self>) {
        let source_id = source.source_id();

        // Check if diff tab already exists anywhere
        if let Some((pane_id, tab_id)) = self.root.find_diff_tab(&source_id) {
            self.active_pane = pane_id;
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            cx.notify();
            return;
        }

        // Create new diff view entity
        if !self.diff_views.contains_key(&source_id) {
            let src = source.clone();
            let diff_view = cx.new(|cx| DiffView::new(src, cx));
            self.diff_views.insert(source_id.clone(), diff_view);
        }

        // Add tab to active pane
        let tab = Tab::new_diff(source);
        if let Some(pane) = self.active_pane_mut() {
            pane.add_tab(tab);
        }

        cx.notify();
    }

    /// Open the file explorer as a sidebar panel.
    ///
    /// If the sidebar already shows this source, toggles it visible.
    /// Otherwise sets the source and shows the sidebar.
    pub fn open_explorer(&mut self, source: FileSource, cx: &mut Context<Self>) {
        self.show_explorer_sidebar(source, cx);
    }

    /// Open an editor tab for a file
    ///
    /// If the tab already exists, switches to it. Otherwise creates a new tab.
    pub fn open_editor(&mut self, source: FileSource, cx: &mut Context<Self>) {
        let source_id = source.source_id();

        // Check if editor tab already exists anywhere
        if let Some((pane_id, tab_id)) = self.root.find_editor_tab(&source_id) {
            self.active_pane = pane_id;
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            cx.notify();
            return;
        }

        // Create new editor entity
        if !self.editor_views.contains_key(&source_id) {
            let src = source.clone();
            let editor = cx.new(|cx| crate::editor::EditorView::new(src, cx));
            self.editor_views.insert(source_id.clone(), editor);
        }

        // Get file name for tab title
        let file_name = source.display_name();
        let tab = Tab::new_editor(source, file_name);
        if let Some(pane) = self.active_pane_mut() {
            pane.add_tab(tab);
        }

        cx.notify();
    }

    /// Handle FileSelected events from explorers
    fn on_file_selected(
        &mut self,
        _explorer: Entity<FileExplorer>,
        event: &FileSelected,
        cx: &mut Context<Self>,
    ) {
        let FileSource::Local { root_path } = &event.source;
        let file_source = FileSource::Local {
            root_path: format!("{}/{}", root_path, event.path),
        };

        self.open_editor(file_source, cx);
    }

    /// Toggle the explorer sidebar visibility.
    ///
    /// If the sidebar has no source yet, this is a no-op (the source must be
    /// set first via `open_explorer` or `show_explorer_sidebar`).
    pub fn toggle_explorer_sidebar(&mut self, cx: &mut Context<Self>) {
        if self.explorer_sidebar_source.is_none() {
            return;
        }
        self.explorer_sidebar_visible = !self.explorer_sidebar_visible;
        cx.notify();
    }

    /// Show the explorer sidebar for a given source, creating the entity if needed.
    pub fn show_explorer_sidebar(&mut self, source: FileSource, cx: &mut Context<Self>) {
        let source_id = source.source_id();

        // Create explorer entity if it doesn't exist
        if !self.explorers.contains_key(&source_id) {
            let src = source.clone();
            let explorer = cx.new(|cx| FileExplorer::new(src, cx));
            cx.subscribe(&explorer, Self::on_file_selected).detach();
            self.explorers.insert(source_id, explorer);
        }

        self.explorer_sidebar_source = Some(source);
        self.explorer_sidebar_visible = true;
        cx.notify();
    }

    /// Get the source_id for the sidebar's explorer entity (if set).
    fn explorer_sidebar_source_id(&self) -> Option<String> {
        self.explorer_sidebar_source.as_ref().map(|s| s.source_id())
    }

    /// Close a tab in a specific pane, checking for unsaved changes first
    pub fn close_tab(&mut self, pane_id: PaneId, tab_id: TabId, cx: &mut Context<Self>) {
        // Check if this is an editor tab with unsaved changes
        if let Some(pane) = self.root.find_pane(pane_id) {
            if let Some(tab) = pane.tabs.iter().find(|t| t.id == tab_id) {
                if let TabContent::Editor {
                    source_id,
                    display_name,
                    ..
                } = &tab.content
                {
                    if let Some(editor) = self.editor_views.get(source_id) {
                        if editor.read(cx).is_modified() {
                            // Show unsaved changes dialog
                            self.unsaved_dialog = Some(UnsavedChangesDialog {
                                pane_id,
                                tab_id,
                                source_id: source_id.clone(),
                                file_name: display_name.clone(),
                            });
                            cx.notify();
                            return;
                        }
                    }
                }
            }
        }
        self.force_close_tab(pane_id, tab_id, cx);
    }

    /// Close a tab without checking for unsaved changes
    fn force_close_tab(&mut self, pane_id: PaneId, tab_id: TabId, cx: &mut Context<Self>) {
        if let Some(pane) = self.root.find_pane_mut(pane_id) {
            // Find the tab to get its content before removing
            let tab_content = pane
                .tabs
                .iter()
                .find(|t| t.id == tab_id)
                .map(|t| t.content.clone());

            pane.remove_tab(tab_id);

            // Clean up associated entity
            match tab_content {
                Some(TabContent::Terminal {
                    workspace_id,
                    session_name,
                    ..
                }) => {
                    self.terminals.remove(&(workspace_id, session_name));
                }
                Some(TabContent::Diff { source_id, .. }) => {
                    self.diff_views.remove(&source_id);
                }
                Some(TabContent::Explorer { source_id, .. }) => {
                    self.explorers.remove(&source_id);
                }
                Some(TabContent::Editor { source_id, .. }) => {
                    self.editor_views.remove(&source_id);
                }
                Some(TabContent::Home { workspace_id }) => {
                    self.home_views.remove(&workspace_id);
                }
                Some(TabContent::WebBrowser { source_id, .. }) => {
                    self.web_browsers.remove(&source_id);
                }
                Some(TabContent::Workspace { .. }) | Some(TabContent::Chat) | None => {}
            }

            // If pane is now empty, close it (unless it's the last pane)
            if pane.tabs.is_empty() {
                let all_panes = self.root.all_pane_ids();
                if all_panes.len() > 1 {
                    let result = self.root.close_pane(pane_id);
                    if matches!(result, CloseResult::Kept | CloseResult::Removed) {
                        // Update active pane to first remaining pane
                        self.active_pane = self.root.first_leaf().id;
                    }
                }
            }
        }

        cx.notify();
    }

    /// Switch to a specific tab in a pane
    pub fn select_tab(&mut self, pane_id: PaneId, tab_id: TabId, cx: &mut Context<Self>) {
        self.active_pane = pane_id;
        if let Some(pane) = self.root.find_pane_mut(pane_id) {
            pane.set_active_tab(tab_id);
        }
        cx.notify();
    }

    /// Set the active pane
    pub fn set_active_pane(&mut self, pane_id: PaneId, cx: &mut Context<Self>) {
        if self.root.contains_pane(pane_id) {
            self.active_pane = pane_id;
            cx.emit(ActivePaneChanged { pane_id });
            cx.notify();
        }
    }

    /// Split the active pane in the given direction
    pub fn split_active_pane(&mut self, direction: SplitDirection, cx: &mut Context<Self>) {
        if let Some(_new_pane_id) = self.root.split(self.active_pane, direction) {
            // Keep focus on the original pane
            // User can click the new pane to activate it
            cx.notify();
        }
    }

    /// Split a specific pane
    pub fn split_pane(
        &mut self,
        pane_id: PaneId,
        direction: SplitDirection,
        cx: &mut Context<Self>,
    ) {
        self.root.split(pane_id, direction);
        cx.notify();
    }

    /// Update the split ratio for a divider
    pub fn set_split_ratio(&mut self, pane_id: PaneId, ratio: f32, cx: &mut Context<Self>) {
        self.root.set_ratio(pane_id, ratio);
        cx.notify();
    }

    /// Focus a pane by its index (0-based, in tree traversal order)
    pub fn focus_pane_by_index(&mut self, index: usize, cx: &mut Context<Self>) {
        let pane_ids = self.root.all_pane_ids();
        if let Some(&pane_id) = pane_ids.get(index) {
            self.set_active_pane(pane_id, cx);
        }
    }

    /// Cycle to the next tab in the active pane (wraps around)
    pub fn next_tab(&mut self, cx: &mut Context<Self>) {
        if let Some(pane) = self.root.find_pane_mut(self.active_pane) {
            if !pane.tabs.is_empty() {
                pane.active_tab = (pane.active_tab + 1) % pane.tabs.len();
                cx.notify();
            }
        }
    }

    /// Cycle to the previous tab in the active pane (wraps around)
    pub fn prev_tab(&mut self, cx: &mut Context<Self>) {
        if let Some(pane) = self.root.find_pane_mut(self.active_pane) {
            if !pane.tabs.is_empty() {
                if pane.active_tab == 0 {
                    pane.active_tab = pane.tabs.len() - 1;
                } else {
                    pane.active_tab -= 1;
                }
                cx.notify();
            }
        }
    }

    /// Select a tab by index in the active pane
    pub fn select_tab_by_index(&mut self, index: usize, cx: &mut Context<Self>) {
        if let Some(pane) = self.root.find_pane_mut(self.active_pane) {
            if index < pane.tabs.len() {
                pane.active_tab = index;
                cx.notify();
            }
        }
    }

    /// Move the active tab from the active pane to another pane by index
    pub fn move_active_tab_to_pane(&mut self, target_index: usize, cx: &mut Context<Self>) {
        let pane_ids = self.root.all_pane_ids();

        // Get target pane ID
        let target_pane_id = match pane_ids.get(target_index) {
            Some(&id) => id,
            None => return,
        };

        // Can't move to the same pane
        if target_pane_id == self.active_pane {
            return;
        }

        // Get the active tab from the active pane
        let tab_to_move = {
            if let Some(pane) = self.root.find_pane(self.active_pane) {
                pane.active_tab().cloned()
            } else {
                None
            }
        };

        if let Some(tab) = tab_to_move {
            let tab_id = tab.id;

            // Remove from source pane
            if let Some(source_pane) = self.root.find_pane_mut(self.active_pane) {
                source_pane.remove_tab(tab_id);
            }

            // Add to target pane
            if let Some(target_pane) = self.root.find_pane_mut(target_pane_id) {
                target_pane.add_tab(tab);
            }

            // Switch to target pane
            self.active_pane = target_pane_id;
            cx.notify();
        }
    }

    /// Handle dropping a tab onto a pane (from drag-and-drop)
    pub fn drop_tab_on_pane(
        &mut self,
        drag_data: TabDragData,
        target_pane_id: PaneId,
        cx: &mut Context<Self>,
    ) {
        // Can't drop on the same pane
        if drag_data.source_pane_id == target_pane_id {
            return;
        }

        let tab_id = drag_data.tab.id;

        // Remove from source pane
        if let Some(source_pane) = self.root.find_pane_mut(drag_data.source_pane_id) {
            source_pane.remove_tab(tab_id);

            // Check if source pane is now empty
            if source_pane.tabs.is_empty() {
                let all_panes = self.root.all_pane_ids();
                if all_panes.len() > 1 {
                    let _ = self.root.close_pane(drag_data.source_pane_id);
                }
            }
        }

        // Add to target pane
        if let Some(target_pane) = self.root.find_pane_mut(target_pane_id) {
            target_pane.add_tab(drag_data.tab);
        }

        // Switch to target pane
        self.active_pane = target_pane_id;
        cx.notify();
    }

    /// Get the index of a pane (for display purposes)
    fn pane_index(&self, pane_id: PaneId) -> Option<usize> {
        self.root
            .all_pane_ids()
            .iter()
            .position(|&id| id == pane_id)
    }

    /// Render the entire pane tree
    fn render_tree(&self, node: &PaneNode, cx: &mut Context<Self>) -> gpui::AnyElement {
        match node {
            PaneNode::Split {
                id,
                direction,
                children,
                ratio,
            } => self.render_split(*id, *direction, children, *ratio, cx),
            PaneNode::Leaf(leaf) => self.render_pane(leaf, cx),
        }
    }

    /// Render a split node with its children and divider
    fn render_split(
        &self,
        split_id: SplitId,
        direction: SplitDirection,
        children: &[Box<PaneNode>; 2],
        ratio: f32,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let theme = Theme::dark();
        let is_horizontal = matches!(direction, SplitDirection::Horizontal);

        let first_child = self.render_tree(&children[0], cx);
        let second_child = self.render_tree(&children[1], cx);

        // Container needs an ID to track bounds for drag calculations.
        // on_children_prepainted measures actual child bounds so drag ratios are accurate.
        let entity = cx.entity().clone();
        let container = div()
            .on_children_prepainted(move |bounds: Vec<Bounds<Pixels>>, _window, cx| {
                let size: f32 = bounds
                    .iter()
                    .map(|b| {
                        if is_horizontal {
                            f32::from(b.size.width)
                        } else {
                            f32::from(b.size.height)
                        }
                    })
                    .sum();
                entity.update(cx, |this: &mut SplitContainer, _cx| {
                    this.split_sizes.insert(split_id, size);
                });
            })
            .id(ElementId::Name(SharedString::from(format!(
                "split-{}",
                split_id.0
            ))))
            .size_full()
            .flex()
            .when(is_horizontal, |d| d.flex_row())
            .when(!is_horizontal, |d| d.flex_col());

        // First child with flex basis
        let first = div()
            .when(is_horizontal, |d| d.w(gpui::relative(ratio)).h_full())
            .when(!is_horizontal, |d| d.h(gpui::relative(ratio)).w_full())
            .overflow_hidden()
            .child(first_child);

        // Divider with drag handling
        let divider = div()
            .id(ElementId::Name(SharedString::from(format!(
                "divider-{}",
                split_id.0
            ))))
            .flex_shrink_0()
            .when(is_horizontal, |d| d.w(px(4.0)).h_full().cursor_col_resize())
            .when(!is_horizontal, |d| {
                d.h(px(4.0)).w_full().cursor_row_resize()
            })
            .hover(|s| s.bg(theme.divider_hover))
            .on_mouse_down(
                gpui::MouseButton::Left,
                cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                    let position: f32 = if is_horizontal {
                        event.position.x.into()
                    } else {
                        event.position.y.into()
                    };
                    this.divider_drag = Some(DividerDrag {
                        split_id,
                        direction,
                        start_position: position,
                        start_ratio: ratio,
                        container_size: this.split_sizes.get(&split_id).copied().unwrap_or(800.0),
                    });
                    cx.notify();
                }),
            );

        // Second child with remaining space
        let second = div().flex_1().overflow_hidden().child(second_child);

        container
            .child(first)
            .child(divider)
            .child(second)
            .on_mouse_move(
                cx.listener(move |this, event: &MouseMoveEvent, _window, cx| {
                    if let Some(drag) = &mut this.divider_drag {
                        if drag.split_id == split_id {
                            let current_position: f32 = if is_horizontal {
                                event.position.x.into()
                            } else {
                                event.position.y.into()
                            };

                            let delta = current_position - drag.start_position;
                            let ratio_delta = delta / drag.container_size;
                            let new_ratio = (drag.start_ratio + ratio_delta).clamp(0.1, 0.9);

                            this.root.set_ratio_by_split_id(split_id, new_ratio);
                            cx.notify();
                        }
                    }
                }),
            )
            .on_mouse_up(
                gpui::MouseButton::Left,
                cx.listener(|this, _event, _window, cx| {
                    this.divider_drag = None;
                    cx.notify();
                }),
            )
            .into_any_element()
    }

    /// Render a single leaf pane with its tab bar and content
    fn render_pane(&self, leaf: &LeafPane, cx: &mut Context<Self>) -> gpui::AnyElement {
        let theme = Theme::dark();
        let pane_id = leaf.id;
        let is_active = pane_id == self.active_pane;
        let has_multiple_panes = self.root.all_pane_ids().len() > 1;

        // Clone data needed for closures
        let tabs = leaf.tabs.clone();
        let active_tab_idx = leaf.active_tab;

        // Build tab bar with inline tab rendering (horizontally scrollable)
        let has_sidebar_source = self.explorer_sidebar_source.is_some();
        let sidebar_visible = self.explorer_sidebar_visible;
        let tab_bar = div()
            .id(ElementId::Name(SharedString::from(format!(
                "tab-bar-{}",
                pane_id.0
            ))))
            .w_full()
            .h(px(32.0))
            .flex()
            .items_end()
            .overflow_x_scroll()
            .font_family(".AppleSystemUIFont")
            // Explorer sidebar toggle icon (only when a sidebar source is set)
            .when(has_sidebar_source, |d| {
                let icon_color = if sidebar_visible {
                    theme.accent
                } else {
                    theme.muted
                };
                d.child(
                    div()
                        .id(ElementId::Name(SharedString::from(format!(
                            "explorer-toggle-{}",
                            pane_id.0
                        ))))
                        .w(px(28.0))
                        .h_full()
                        .flex()
                        .flex_shrink_0()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .hover(|s| s.bg(Theme::dark().hover))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.toggle_explorer_sidebar(cx);
                        }))
                        .child(
                            svg()
                                .path("icons/folder.svg")
                                .size(px(16.0))
                                .text_color(icon_color),
                        ),
                )
            })
            .children(tabs.iter().enumerate().map(|(idx, tab)| {
                let is_active_tab = idx == active_tab_idx;
                let tab_id = tab.id;
                let tab_clone = tab.clone();

                let tab_bg = if is_active_tab {
                    theme.surface
                } else {
                    theme.background
                };

                let tab_fg = if is_active_tab {
                    theme.foreground
                } else {
                    theme.muted
                };

                // Create drag data for this tab
                let drag_data = TabDragData {
                    source_pane_id: pane_id,
                    tab: tab_clone.clone(),
                };

                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "tab-{}-{}",
                        pane_id.0, tab.id.0
                    ))))
                    .h_full()
                    .px_2()
                    .flex()
                    .flex_shrink_0()
                    .items_center()
                    .gap_2()
                    .bg(tab_bg)
                    .when(is_active_tab, |d| {
                        d.rounded_t(px(8.0))
                            .border_t_1()
                            .border_l_1()
                            .border_r_1()
                            .border_color(theme.border)
                    })
                    .cursor_pointer()
                    .when(!is_active_tab, |d| {
                        d.hover(|s| s.bg(theme.hover).rounded_t(px(8.0)))
                    })
                    // Make tab draggable
                    .on_drag(drag_data, |drag_data, _event, _window, cx| {
                        cx.new(|_cx| TabDragPreview {
                            title: drag_data.tab.title.clone(),
                        })
                    })
                    .on_click(cx.listener(move |this, _event, _window, cx| {
                        this.context_menu = None;
                        this.select_tab(pane_id, tab_id, cx);
                    }))
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                            let (tab_index, tab_count) = this
                                .root
                                .find_pane(pane_id)
                                .map(|p| {
                                    let idx =
                                        p.tabs.iter().position(|t| t.id == tab_id).unwrap_or(0);
                                    (idx, p.tabs.len())
                                })
                                .unwrap_or((0, 0));
                            this.context_menu = Some(InnerContextMenu {
                                position: event.position,
                                pane_id,
                                tab_id,
                                tab_index,
                                tab_count,
                            });
                            cx.notify();
                        }),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(tab_fg)
                            .max_w(px(120.0))
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .child(tab.title.clone()),
                    )
                    .child(
                        div()
                            .id(ElementId::Name(SharedString::from(format!(
                                "tab-close-{}-{}",
                                pane_id.0, tab.id.0
                            ))))
                            .w(px(16.0))
                            .h(px(16.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(2.0))
                            .text_color(theme.muted)
                            .hover(|s| s.bg(theme.border).text_color(theme.foreground))
                            .on_click(cx.listener(move |this, _event, _window, cx| {
                                this.close_tab(pane_id, tab_id, cx);
                            }))
                            .child(
                                svg()
                                    .path("icons/close.svg")
                                    .size(px(12.0))
                                    .text_color(theme.muted),
                            ),
                    )
            }))
            // Spacer
            .child(div().flex_1())
            // Pane index indicator (for keyboard navigation reference)
            .child({
                let pane_index = self.pane_index(pane_id).map(|i| i + 1).unwrap_or(0);
                div()
                    .px_2()
                    .text_size(px(10.0))
                    .text_color(theme.muted)
                    .child(format!("^{}", pane_index))
            })
            // Split buttons
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .pr_2()
                    // Split right button
                    .child(
                        icon_button("icons/split-horizontal.svg", 14.0, theme.muted, &theme)
                            .id(ElementId::Name(SharedString::from(format!(
                                "split-right-{}",
                                pane_id.0
                            ))))
                            .on_click(cx.listener(move |this, _event, _window, cx| {
                                this.split_pane(pane_id, SplitDirection::Horizontal, cx);
                            })),
                    )
                    // Split down button
                    .child(
                        icon_button("icons/split-vertical.svg", 14.0, theme.muted, &theme)
                            .id(ElementId::Name(SharedString::from(format!(
                                "split-down-{}",
                                pane_id.0
                            ))))
                            .on_click(cx.listener(move |this, _event, _window, cx| {
                                this.split_pane(pane_id, SplitDirection::Vertical, cx);
                            })),
                    ),
            );

        // Manage web browser visibility: hide all webviews in this pane
        // that are not the active tab, show the one that is active.
        {
            let active_source_id = tabs.get(active_tab_idx).and_then(|t| {
                if let TabContent::WebBrowser { source_id, .. } = &t.content {
                    Some(source_id.clone())
                } else {
                    None
                }
            });
            for tab in &tabs {
                if let TabContent::WebBrowser { source_id, .. } = &tab.content {
                    if let Some(browser) = self.web_browsers.get(source_id) {
                        let should_show = active_source_id.as_deref() == Some(source_id.as_str());
                        browser.update(cx, |b, cx| b.set_visible(should_show, cx));
                    }
                }
            }
        }

        // Render content based on active tab
        let content: gpui::AnyElement = if let Some(active_tab) = tabs.get(active_tab_idx) {
            match &active_tab.content {
                TabContent::Terminal {
                    workspace_id,
                    session_name,
                    ..
                } => {
                    let key = (workspace_id.clone(), session_name.clone());
                    if let Some(terminal) = self.terminals.get(&key) {
                        terminal.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Terminal not found")
                            .into_any_element()
                    }
                }
                TabContent::Chat => self.chat_panel.clone().into_any_element(),
                TabContent::Diff { source_id, .. } => {
                    if let Some(diff_view) = self.diff_views.get(source_id) {
                        diff_view.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Diff view not found")
                            .into_any_element()
                    }
                }
                TabContent::Explorer { source_id, .. } => {
                    if let Some(explorer) = self.explorers.get(source_id) {
                        explorer.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Explorer not found")
                            .into_any_element()
                    }
                }
                TabContent::Editor { source_id, .. } => {
                    if let Some(editor) = self.editor_views.get(source_id) {
                        editor.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Editor not found")
                            .into_any_element()
                    }
                }
                TabContent::Home { workspace_id } => {
                    if let Some(home) = self.home_views.get(workspace_id) {
                        home.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Home")
                            .into_any_element()
                    }
                }
                TabContent::Workspace { display_name, .. } => {
                    // Workspace tabs are rendered at the outer level;
                    // if encountered here, show a placeholder.
                    div()
                        .flex_1()
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_color(theme.muted)
                        .child(format!("Workspace: {}", display_name))
                        .into_any_element()
                }
                TabContent::WebBrowser { source_id, .. } => {
                    if let Some(browser) = self.web_browsers.get(source_id) {
                        browser.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Browser not found")
                            .into_any_element()
                    }
                }
            }
        } else {
            // Empty pane placeholder
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_color(theme.muted)
                .child("Empty pane - click a session to open")
                .into_any_element()
        };

        // Pane container — uses relative positioning so children can be absolute.
        // Content is rendered FIRST (paints underneath), tab bar SECOND (paints on top).
        // This lets the active tab's bg(surface) cover the content's top border,
        // creating a seamless tab-to-content connection.
        div()
            .id(ElementId::Name(SharedString::from(format!(
                "pane-{}",
                pane_id.0
            ))))
            .size_full()
            .relative()
            .bg(theme.background)
            .overflow_hidden()
            // Visual feedback when dragging over this pane
            .drag_over::<TabDragData>(|style, _, _window, _cx| {
                style.border_2().border_color(Theme::dark().accent)
            })
            // Handle tab drops
            .on_drop(
                cx.listener(move |this, drag_data: &TabDragData, _window, cx| {
                    this.drop_tab_on_pane(drag_data.clone(), pane_id, cx);
                }),
            )
            .on_click(cx.listener(move |this, _event, _window, cx| {
                this.set_active_pane(pane_id, cx);
            }))
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                    // Don't override tab-level menu (tab handler fires first on inner elements)
                    if this.context_menu.is_some() {
                        return;
                    }
                    let (tab_id, tab_index, tab_count) = this
                        .root
                        .find_pane(pane_id)
                        .map(|p| {
                            let idx = p.active_tab.min(p.tabs.len().saturating_sub(1));
                            (p.tabs[idx].id, idx, p.tabs.len())
                        })
                        .unwrap_or_else(|| (TabId(0), 0, 0));
                    this.context_menu = Some(InnerContextMenu {
                        position: event.position,
                        pane_id,
                        tab_id,
                        tab_index,
                        tab_count,
                    });
                    cx.notify();
                }),
            )
            // Content — painted first (underneath tab bar)
            .child(
                div()
                    .absolute()
                    .top(px(31.0))
                    .bottom(px(0.0))
                    .left(px(0.0))
                    .right(px(0.0))
                    .overflow_hidden()
                    .bg(theme.surface)
                    .border_1()
                    .border_color(theme.border)
                    .rounded(px(8.0))
                    .child(content),
            )
            // Tab bar — painted second (on top), active tab covers content's top border
            .child(tab_bar)
            .into_any_element()
    }
}

impl SplitContainer {
    /// Connect a terminal view based on the persisted connection type.
    fn connect_terminal(
        t: &mut TerminalView,
        connection: &TerminalConnection,
        cx: &mut Context<TerminalView>,
    ) {
        match connection {
            TerminalConnection::Local => t.connect_local(cx),
            TerminalConnection::CodewireEnvironment {
                org_id,
                env_id,
                env_name,
            } => {
                t.connect_codewire_env(org_id, env_id, env_name, cx);
            }
        }
    }

    /// Ensure entities exist for all tabs in the tree (for restored layouts).
    /// Called at the start of render to lazily create entities for persisted tabs.
    fn ensure_tab_entities(&mut self, cx: &mut Context<Self>) {
        let tabs: Vec<TabContent> = self.collect_all_tab_contents();
        for content in tabs {
            match content {
                TabContent::Terminal {
                    workspace_id,
                    session_name,
                    connection,
                    ..
                } => {
                    let key = (workspace_id, session_name.clone());
                    if !self.terminals.contains_key(&key) {
                        let conn = connection.clone();
                        let terminal = cx.new(|cx| TerminalView::new(cx));
                        terminal.update(cx, |t, cx| {
                            Self::connect_terminal(t, &conn, cx);
                        });
                        self.terminals.insert(key, terminal);
                    }
                }
                TabContent::Diff {
                    source_id, source, ..
                } => {
                    if !self.diff_views.contains_key(&source_id) {
                        let diff_view = cx.new(|cx| DiffView::new(source, cx));
                        self.diff_views.insert(source_id, diff_view);
                    }
                }
                TabContent::Explorer {
                    source_id, source, ..
                } => {
                    if !self.explorers.contains_key(&source_id) {
                        let explorer = cx.new(|cx| FileExplorer::new(source, cx));
                        cx.subscribe(&explorer, Self::on_file_selected).detach();
                        self.explorers.insert(source_id, explorer);
                    }
                }
                TabContent::Editor {
                    source_id, source, ..
                } => {
                    if !self.editor_views.contains_key(&source_id) {
                        let editor = cx.new(|cx| crate::editor::EditorView::new(source, cx));
                        self.editor_views.insert(source_id, editor);
                    }
                }
                TabContent::Home { workspace_id } => {
                    if !self.home_views.contains_key(&workspace_id) {
                        if let Some(identity) = &self.workspace_identity {
                            let id = identity.clone();
                            let home = cx.new(|cx| WorkspaceHome::new(id, cx));
                            self.home_views.insert(workspace_id, home);
                        }
                    }
                }
                TabContent::WebBrowser { url, source_id } => {
                    if !self.web_browsers.contains_key(&source_id) {
                        let browser = cx.new(|cx| WebBrowserView::new(url, None, cx));
                        self.web_browsers.insert(source_id, browser);
                    }
                }
                TabContent::Chat | TabContent::Workspace { .. } => {}
            }
        }
    }

    /// Collect all tab contents from the pane tree.
    fn collect_all_tab_contents(&self) -> Vec<TabContent> {
        let mut contents = Vec::new();
        self.collect_tab_contents_from_node(&self.root, &mut contents);
        contents
    }

    /// Close a pane (remove all its tabs and collapse the split)
    fn close_pane(&mut self, pane_id: PaneId, cx: &mut Context<Self>) {
        // Collect tabs to clean up entities
        if let Some(pane) = self.root.find_pane(pane_id) {
            let tab_contents: Vec<TabContent> =
                pane.tabs.iter().map(|t| t.content.clone()).collect();
            for content in tab_contents {
                match content {
                    TabContent::Terminal {
                        workspace_id,
                        session_name,
                        ..
                    } => {
                        self.terminals.remove(&(workspace_id, session_name));
                    }
                    TabContent::Diff { source_id, .. } => {
                        self.diff_views.remove(&source_id);
                    }
                    TabContent::Explorer { source_id, .. } => {
                        self.explorers.remove(&source_id);
                    }
                    TabContent::Editor { source_id, .. } => {
                        self.editor_views.remove(&source_id);
                    }
                    TabContent::Home { workspace_id } => {
                        self.home_views.remove(&workspace_id);
                    }
                    TabContent::WebBrowser { source_id, .. } => {
                        self.web_browsers.remove(&source_id);
                    }
                    TabContent::Chat | TabContent::Workspace { .. } => {}
                }
            }
        }

        let all_panes = self.root.all_pane_ids();
        if all_panes.len() > 1 {
            let _ = self.root.close_pane(pane_id);
            self.active_pane = self.root.first_leaf().id;
        }

        cx.notify();
    }

    /// Close all tabs in a pane except the specified one
    fn close_other_tabs(&mut self, pane_id: PaneId, keep_tab_id: TabId, cx: &mut Context<Self>) {
        let tabs_to_close: Vec<(TabId, TabContent)> =
            if let Some(pane) = self.root.find_pane(pane_id) {
                pane.tabs
                    .iter()
                    .filter(|t| t.id != keep_tab_id)
                    .map(|t| (t.id, t.content.clone()))
                    .collect()
            } else {
                return;
            };

        for (tid, content) in &tabs_to_close {
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.remove_tab(*tid);
            }
            self.cleanup_tab_entity(content);
        }

        cx.notify();
    }

    /// Close tabs to the right of the specified tab
    fn close_tabs_to_right(&mut self, pane_id: PaneId, tab_id: TabId, cx: &mut Context<Self>) {
        let tabs_to_close: Vec<(TabId, TabContent)> =
            if let Some(pane) = self.root.find_pane(pane_id) {
                if let Some(idx) = pane.tabs.iter().position(|t| t.id == tab_id) {
                    pane.tabs[idx + 1..]
                        .iter()
                        .map(|t| (t.id, t.content.clone()))
                        .collect()
                } else {
                    return;
                }
            } else {
                return;
            };

        for (tid, content) in &tabs_to_close {
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.remove_tab(*tid);
            }
            self.cleanup_tab_entity(content);
        }

        cx.notify();
    }

    /// Close tabs to the left of the specified tab
    fn close_tabs_to_left(&mut self, pane_id: PaneId, tab_id: TabId, cx: &mut Context<Self>) {
        let tabs_to_close: Vec<(TabId, TabContent)> =
            if let Some(pane) = self.root.find_pane(pane_id) {
                if let Some(idx) = pane.tabs.iter().position(|t| t.id == tab_id) {
                    pane.tabs[..idx]
                        .iter()
                        .map(|t| (t.id, t.content.clone()))
                        .collect()
                } else {
                    return;
                }
            } else {
                return;
            };

        for (tid, content) in &tabs_to_close {
            if let Some(pane) = self.root.find_pane_mut(pane_id) {
                pane.remove_tab(*tid);
            }
            self.cleanup_tab_entity(content);
        }

        cx.notify();
    }

    /// Close all tabs in a pane. If multiple panes exist, closes the pane itself.
    fn close_all_tabs(&mut self, pane_id: PaneId, cx: &mut Context<Self>) {
        let all_panes = self.root.all_pane_ids();
        if all_panes.len() > 1 {
            // Multiple panes: close the entire pane
            self.close_pane(pane_id, cx);
        } else {
            // Single pane: close all tabs but keep the pane
            let tabs_to_close: Vec<(TabId, TabContent)> =
                if let Some(pane) = self.root.find_pane(pane_id) {
                    pane.tabs
                        .iter()
                        .map(|t| (t.id, t.content.clone()))
                        .collect()
                } else {
                    return;
                };

            for (tid, content) in &tabs_to_close {
                if let Some(pane) = self.root.find_pane_mut(pane_id) {
                    pane.remove_tab(*tid);
                }
                self.cleanup_tab_entity(content);
            }

            cx.notify();
        }
    }

    /// Clean up entity resources associated with a tab content
    fn cleanup_tab_entity(&mut self, content: &TabContent) {
        match content {
            TabContent::Terminal {
                workspace_id,
                session_name,
                ..
            } => {
                self.terminals
                    .remove(&(workspace_id.clone(), session_name.clone()));
            }
            TabContent::Diff { source_id, .. } => {
                self.diff_views.remove(source_id);
            }
            TabContent::Explorer { source_id, .. } => {
                self.explorers.remove(source_id);
            }
            TabContent::Editor { source_id, .. } => {
                self.editor_views.remove(source_id);
            }
            TabContent::Home { workspace_id } => {
                self.home_views.remove(workspace_id);
            }
            TabContent::WebBrowser { source_id, .. } => {
                self.web_browsers.remove(source_id);
            }
            TabContent::Chat | TabContent::Workspace { .. } => {}
        }
    }

    /// Render the right-click context menu for inner tabs
    fn render_context_menu(
        &self,
        menu: &InnerContextMenu,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let theme = Theme::dark();
        let pos = menu.position;
        let pane_id = menu.pane_id;
        let tab_id = menu.tab_id;
        let tab_index = menu.tab_index;
        let tab_count = menu.tab_count;
        let has_multiple_panes = self.root.all_pane_ids().len() > 1;

        // Dismiss overlay — uses on_click (not on_mouse_down) so it doesn't
        // steal the pending mouse-down from menu items' on_click handlers.
        let dismiss = div()
            .id("inner-ctx-dismiss")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .on_click(cx.listener(|this, _, _, cx| {
                this.context_menu = None;
                cx.notify();
            }))
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(|this, _, _, cx| {
                    this.context_menu = None;
                    cx.notify();
                }),
            );

        let item_style = |id: &str, label: &str| {
            div()
                .id(ElementId::Name(SharedString::from(id.to_string())))
                .px(px(12.0))
                .py(px(6.0))
                .text_size(px(13.0))
                .text_color(theme.foreground)
                .cursor_pointer()
                .hover(|s| s.bg(theme.hover))
                .rounded(px(3.0))
                .mx(px(4.0))
                .child(label.to_string())
        };

        let separator = || div().h(px(1.0)).mx(px(8.0)).my(px(4.0)).bg(theme.border);

        let menu_panel = div()
            .w(px(200.0))
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .rounded(px(6.0))
            .py(px(4.0))
            .shadow_lg()
            // Close Tab
            .child(
                item_style("inner-ctx-close-tab", "Close Tab").on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        this.close_tab(pane_id, tab_id, cx);
                    },
                )),
            )
            // Close Other Tabs (only if >1 tab)
            .when(tab_count > 1, |d| {
                d.child(
                    item_style("inner-ctx-close-others", "Close Other Tabs").on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_other_tabs(pane_id, tab_id, cx);
                        },
                    )),
                )
            })
            // Close Tabs to the Right (only if not last tab)
            .when(tab_index + 1 < tab_count, |d| {
                d.child(
                    item_style("inner-ctx-close-right", "Close Tabs to the Right").on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_tabs_to_right(pane_id, tab_id, cx);
                        }),
                    ),
                )
            })
            // Close Tabs to the Left (only if not first tab)
            .when(tab_index > 0, |d| {
                d.child(
                    item_style("inner-ctx-close-left", "Close Tabs to the Left").on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_tabs_to_left(pane_id, tab_id, cx);
                        }),
                    ),
                )
            })
            // Separator
            .child(separator())
            // Split Right
            .child(
                item_style("inner-ctx-split-right", "Split Right").on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        this.split_pane(pane_id, SplitDirection::Horizontal, cx);
                    },
                )),
            )
            // Split Down
            .child(
                item_style("inner-ctx-split-down", "Split Down").on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        this.split_pane(pane_id, SplitDirection::Vertical, cx);
                    },
                )),
            )
            // Separator
            .child(separator())
            // Close All Tabs
            .child(
                item_style("inner-ctx-close-all", "Close All Tabs").on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        this.close_all_tabs(pane_id, cx);
                    },
                )),
            )
            // Close Pane (only if >1 pane)
            .when(has_multiple_panes, |d| {
                d.child(
                    item_style("inner-ctx-close-pane", "Close Pane").on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_pane(pane_id, cx);
                        },
                    )),
                )
            });

        div()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .child(dismiss)
            .child(anchored().position(pos).snap_to_window().child(menu_panel))
            .into_any_element()
    }

    /// Render the unsaved changes confirmation dialog
    fn render_unsaved_dialog(
        &self,
        dialog: &UnsavedChangesDialog,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let theme = Theme::dark();
        let pane_id = dialog.pane_id;
        let tab_id = dialog.tab_id;
        let source_id = dialog.source_id.clone();
        let file_name = dialog.file_name.clone();

        let button_style = |id: &str, label: &str, is_primary: bool| {
            let bg = if is_primary {
                theme.accent
            } else {
                theme.surface
            };
            div()
                .id(ElementId::Name(SharedString::from(id.to_string())))
                .px(px(16.0))
                .py(px(6.0))
                .rounded(px(4.0))
                .bg(bg)
                .border_1()
                .border_color(theme.border)
                .text_size(px(13.0))
                .text_color(theme.foreground)
                .cursor_pointer()
                .hover(|s| {
                    s.bg(if is_primary {
                        theme.divider_hover
                    } else {
                        theme.hover
                    })
                })
                .child(label.to_string())
        };

        // Dismiss overlay
        let dismiss = div()
            .id("unsaved-dismiss")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .bg(gpui::hsla(0.0, 0.0, 0.0, 0.5));

        let source_id_for_save = source_id.clone();

        let dialog_panel = div()
            .w(px(400.0))
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .rounded(px(8.0))
            .p(px(20.0))
            .shadow_lg()
            .flex()
            .flex_col()
            .gap_4()
            // Title
            .child(
                div()
                    .text_size(px(14.0))
                    .text_color(theme.foreground)
                    .child(format!("Do you want to save changes to {}?", file_name)),
            )
            // Subtitle
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(theme.muted)
                    .child("Your changes will be lost if you don't save them."),
            )
            // Buttons row
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    // Cancel
                    .child(
                        button_style("unsaved-cancel", "Cancel", false).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.unsaved_dialog = None;
                                cx.notify();
                            },
                        )),
                    )
                    // Don't Save
                    .child(
                        button_style("unsaved-dont-save", "Don't Save", false).on_click(
                            cx.listener(move |this, _, _, cx| {
                                this.unsaved_dialog = None;
                                this.force_close_tab(pane_id, tab_id, cx);
                            }),
                        ),
                    )
                    // Save
                    .child(
                        button_style("unsaved-save", "Save", true).on_click(cx.listener(
                            move |this, _, window, cx| {
                                this.unsaved_dialog = None;
                                // Trigger save on the editor, then close
                                if let Some(editor) = this.editor_views.get(&source_id_for_save) {
                                    editor.update(cx, |editor, cx| {
                                        editor.save_file(&crate::editor::SaveFile, window, cx);
                                    });
                                }
                                this.force_close_tab(pane_id, tab_id, cx);
                            },
                        )),
                    ),
            );

        div()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .child(dismiss)
            .child(dialog_panel)
            .into_any_element()
    }

    fn collect_tab_contents_from_node(&self, node: &PaneNode, out: &mut Vec<TabContent>) {
        match node {
            PaneNode::Split { children, .. } => {
                self.collect_tab_contents_from_node(&children[0], out);
                self.collect_tab_contents_from_node(&children[1], out);
            }
            PaneNode::Leaf(leaf) => {
                for tab in &leaf.tabs {
                    out.push(tab.content.clone());
                }
            }
        }
    }
}

impl Focusable for SplitContainer {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for SplitContainer {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Lazily create entities for restored tabs (from persisted layout)
        self.ensure_tab_entities(cx);

        let theme = Theme::dark();
        let pane_tree = self.render_tree(&self.root.clone(), cx);

        // Build content area: optional sidebar + pane tree
        let mut content = div().size_full().flex().flex_row();

        if self.explorer_sidebar_visible {
            if let Some(source_id) = self.explorer_sidebar_source_id() {
                if let Some(explorer) = self.explorers.get(&source_id) {
                    let sidebar_width = self.explorer_sidebar_width;

                    // Sidebar panel
                    content = content.child(
                        div()
                            .w(px(sidebar_width))
                            .h_full()
                            .flex_shrink_0()
                            .overflow_hidden()
                            .border_r_1()
                            .border_color(theme.border)
                            .child(explorer.clone()),
                    );

                    // Drag handle (4px vertical divider)
                    content = content.child(
                        div()
                            .id("explorer-sidebar-divider")
                            .w(px(4.0))
                            .h_full()
                            .flex_shrink_0()
                            .cursor_col_resize()
                            .bg(theme.border)
                            .hover(|s| s.bg(Theme::dark().divider_hover))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                                    this.sidebar_drag = Some(SidebarDrag {
                                        start_x: event.position.x.into(),
                                        start_width: this.explorer_sidebar_width,
                                    });
                                    cx.notify();
                                }),
                            ),
                    );
                }
            }
        }

        // Pane tree takes remaining space
        content = content.child(div().flex_1().overflow_hidden().child(pane_tree));

        let mut root = div()
            .relative()
            .size_full()
            .bg(theme.background)
            .track_focus(&self.focus_handle(cx))
            .child(content)
            // Sidebar drag resize handlers (on root so drags work even if mouse leaves handle)
            .on_mouse_move(cx.listener(|this, event: &MouseMoveEvent, _window, cx| {
                if let Some(drag) = &this.sidebar_drag {
                    let current_x: f32 = event.position.x.into();
                    let delta = current_x - drag.start_x;
                    let new_width = (drag.start_width + delta).clamp(150.0, 500.0);
                    this.explorer_sidebar_width = new_width;
                    cx.notify();
                }
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _event, _window, cx| {
                    if this.sidebar_drag.is_some() {
                        this.sidebar_drag = None;
                        cx.notify();
                    }
                }),
            );

        if let Some(menu) = self.context_menu.clone() {
            root = root.child(self.render_context_menu(&menu, cx));
        }

        if let Some(dialog) = self.unsaved_dialog.clone() {
            root = root.child(self.render_unsaved_dialog(&dialog, cx));
        }

        root
    }
}
