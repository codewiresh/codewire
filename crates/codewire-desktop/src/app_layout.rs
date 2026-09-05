//! Outer workspace container that manages multiple workspace split containers.
//!
//! AppLayout owns the outer-level PaneNode tree (workspace-level splits) and
//! a HashMap of per-workspace SplitContainers. Each workspace gets its own
//! independent split layout with inner tabs.

use crate::chat::ChatPanel;
use crate::layout_storage::{AppLayoutState, LayoutStorage, WindowId};
use crate::pane_tree::{
    LeafPane, PaneId, PaneNode, SplitDirection, SplitId, Tab, TabContent, TabId,
};
use crate::split_container::SplitContainer;
use crate::theme::Theme;
use crate::workspace::WorkspaceIdentity;
use crate::{AppState, MoveWorkspaceToWindow};
use gpui::{
    App, Bounds, Context, ElementId, Entity, FocusHandle, Focusable, Global, MouseButton,
    MouseDownEvent, MouseMoveEvent, Pixels, Point, SharedString, Window, anchored, div, prelude::*,
    px, svg,
};

/// Data transferred when dragging a workspace tab between outer panes
#[derive(Clone, Debug)]
struct WorkspaceTabDragData {
    source_window_id: WindowId,
    source_pane_id: PaneId,
    tab: Tab,
}

/// Visual preview shown while dragging a workspace tab
struct WorkspaceTabDragPreview {
    title: String,
}

impl Render for WorkspaceTabDragPreview {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();
        div()
            .px_3()
            .py_1()
            .bg(theme.surface)
            .border_1()
            .border_color(theme.accent)
            .rounded(px(4.0))
            .text_size(px(13.0))
            .text_color(theme.foreground)
            .child(self.title.clone())
    }
}
use std::collections::HashMap;

/// State for tracking an active outer divider drag
#[derive(Clone, Copy, Debug)]
struct OuterDividerDrag {
    split_id: SplitId,
    direction: SplitDirection,
    start_position: f32,
    start_ratio: f32,
    container_size: f32,
}

/// Context menu state for workspace tabs
#[derive(Clone, Debug)]
struct ContextMenu {
    position: Point<Pixels>,
    pane_id: PaneId,
    tab_id: TabId,
    workspace_id: Option<String>,
    tab_index: usize,
    tab_count: usize,
}

/// Outer workspace container managing workspace-level splits.
pub struct AppLayout {
    /// This window's unique identifier (for per-window layout persistence)
    window_id: WindowId,
    /// Workspace-level pane tree (outer splits)
    outer_tree: PaneNode,
    /// Currently focused outer pane
    active_outer_pane: PaneId,
    /// Per-workspace SplitContainers
    workspaces: HashMap<String, Entity<SplitContainer>>,
    /// Shared chat panel (passed to each workspace's SplitContainer)
    chat_panel: Entity<ChatPanel>,
    /// Active outer divider drag state
    outer_divider_drag: Option<OuterDividerDrag>,
    /// Measured container sizes for each outer split node
    outer_split_sizes: HashMap<SplitId, f32>,
    /// Right-click context menu
    context_menu: Option<ContextMenu>,
    /// Persistent layout storage
    layout_storage: Option<LayoutStorage>,
    focus_handle: FocusHandle,
}

impl AppLayout {
    /// Create a new AppLayout for a window. If `restore` is Some, restores that saved layout.
    /// Otherwise starts fresh. The `window_id` identifies this window for layout persistence.
    pub fn new(
        window_id: WindowId,
        chat_panel: Entity<ChatPanel>,
        restore: Option<AppLayoutState>,
        cx: &mut Context<Self>,
    ) -> Self {
        let layout_storage = LayoutStorage::new().ok();

        // Try to restore from provided layout state
        if let Some(saved) = restore {
            let mut workspaces = HashMap::new();
            for (ws_id, identity) in &saved.workspace_identities {
                let chat = chat_panel.clone();
                let ws_identity = identity.clone();
                let ws_layout = saved.workspace_layouts.get(ws_id);
                let container = cx.new(|cx| {
                    let mut sc = SplitContainer::new(chat, cx);
                    sc.set_workspace_identity(ws_identity.clone());
                    if let Some(layout) = ws_layout {
                        sc.restore_layout(layout.root.clone(), layout.active_pane);
                    } else {
                        sc.open_home(ws_identity, cx);
                    }
                    sc
                });
                workspaces.insert(ws_id.clone(), container);
            }

            if !workspaces.is_empty() {
                // Strip stale Chat tabs from restored layout
                let mut outer_tree = saved.outer_tree;
                outer_tree.remove_tabs_by(&|t| matches!(t.content, TabContent::Chat));

                // Reset ID counters past the max restored IDs to avoid collision
                let (mut max_pane, mut max_split, mut max_tab) = outer_tree.max_ids();
                for (_, container) in &workspaces {
                    let (p, s, t) = container.read(cx).root_node().max_ids();
                    max_pane = max_pane.max(p);
                    max_split = max_split.max(s);
                    max_tab = max_tab.max(t);
                }
                PaneId::reset_counter(max_pane);
                SplitId::reset_counter(max_split);
                TabId::reset_counter(max_tab);

                tracing::info!(
                    "Restored layout for window {} with {} workspaces (counters: pane>{}, split>{}, tab>{})",
                    window_id.0,
                    workspaces.len(),
                    max_pane,
                    max_split,
                    max_tab
                );
                return Self {
                    window_id,
                    outer_tree,
                    active_outer_pane: saved.active_outer_pane,
                    workspaces,
                    chat_panel,
                    outer_divider_drag: None,
                    outer_split_sizes: HashMap::new(),
                    context_menu: None,
                    layout_storage,
                    focus_handle: cx.focus_handle(),
                };
            }
        }

        // Default: start fresh with a Chat tab
        let initial_pane = LeafPane::new_with_tab(Tab::new_chat());
        let active_outer_pane = initial_pane.id;

        let default_container = cx.new(|cx| SplitContainer::new(chat_panel.clone(), cx));
        let mut workspaces = HashMap::new();
        workspaces.insert("__default__".to_string(), default_container);

        Self {
            window_id,
            outer_tree: PaneNode::Leaf(initial_pane),
            active_outer_pane,
            workspaces,
            chat_panel,
            outer_divider_drag: None,
            outer_split_sizes: HashMap::new(),
            context_menu: None,
            layout_storage,
            focus_handle: cx.focus_handle(),
        }
    }

    /// Get this window's ID.
    pub fn window_id(&self) -> &WindowId {
        &self.window_id
    }

    /// Open (or switch to) a workspace. Returns the workspace's SplitContainer.
    pub fn open_workspace(
        &mut self,
        identity: WorkspaceIdentity,
        cx: &mut Context<Self>,
    ) -> Entity<SplitContainer> {
        let workspace_id = identity.id.clone();

        // Check if workspace tab already exists in the outer tree
        if let Some((pane_id, tab_id)) = self.outer_tree.find_workspace_tab(&workspace_id) {
            // Switch to existing workspace tab
            self.active_outer_pane = pane_id;
            if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            cx.notify();
            return self.workspaces.get(&workspace_id).cloned().unwrap();
        }

        // Create new SplitContainer for this workspace
        let chat = self.chat_panel.clone();
        let ws_identity = identity.clone();
        let container = cx.new(|cx| {
            let mut sc = SplitContainer::new(chat, cx);
            sc.set_workspace_identity(ws_identity.clone());
            // Open a Home tab as the default view
            sc.open_home(ws_identity, cx);
            sc
        });
        self.workspaces
            .insert(workspace_id.clone(), container.clone());

        // Remove the default container if this is the first real workspace
        if self.workspaces.contains_key("__default__") && self.workspaces.len() > 2 {
            // Keep __default__ around until we have at least one real workspace
        }

        // Add workspace tab — auto-split if active pane already has a workspace
        let tab = Tab::new_workspace(workspace_id, identity.name);

        let active_has_workspace = self
            .outer_tree
            .find_pane(self.active_outer_pane)
            .map(|pane| {
                pane.tabs
                    .iter()
                    .any(|t| matches!(t.content, TabContent::Workspace { .. }))
            })
            .unwrap_or(false);

        let target_pane_id = if active_has_workspace {
            // Split horizontally to give the new workspace its own pane
            self.outer_tree
                .split(self.active_outer_pane, SplitDirection::Horizontal)
                .unwrap_or(self.active_outer_pane)
        } else {
            self.active_outer_pane
        };

        if let Some(pane) = self.outer_tree.find_pane_mut(target_pane_id) {
            // If the pane only has a Chat tab (default state), replace it
            if pane.tabs.len() == 1 {
                if let Some(TabContent::Chat) = pane.tabs.first().map(|t| &t.content) {
                    pane.tabs.clear();
                }
            }
            pane.add_tab(tab);
        }
        self.active_outer_pane = target_pane_id;

        self.save_layout(cx);
        cx.notify();
        container
    }

    /// Activate an existing workspace by ID.
    pub fn activate_workspace(&mut self, workspace_id: &str, cx: &mut Context<Self>) {
        if let Some((pane_id, tab_id)) = self.outer_tree.find_workspace_tab(workspace_id) {
            self.active_outer_pane = pane_id;
            if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
                pane.set_active_tab(tab_id);
            }
            self.save_layout(cx);
            cx.notify();
        }
    }

    /// Close a workspace by ID.
    pub fn close_workspace(&mut self, workspace_id: &str, cx: &mut Context<Self>) {
        // Find and remove the workspace tab from the outer tree
        if let Some((pane_id, tab_id)) = self.outer_tree.find_workspace_tab(workspace_id) {
            if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
                pane.remove_tab(tab_id);

                // If pane is now empty, close it (unless it's the last pane)
                if pane.tabs.is_empty() {
                    let all_panes = self.outer_tree.all_pane_ids();
                    if all_panes.len() > 1 {
                        let _ = self.outer_tree.close_pane(pane_id);
                        self.active_outer_pane = self.outer_tree.first_leaf().id;
                    }
                }
            }
        }

        // Drop the SplitContainer entity
        self.workspaces.remove(workspace_id);
        self.save_layout(cx);
        cx.notify();
    }

    /// Check if this layout contains a workspace with the given ID.
    pub fn has_workspace(&self, workspace_id: &str) -> bool {
        self.workspaces.contains_key(workspace_id)
    }

    /// Detach a workspace from this layout, returning the tab, container entity,
    /// and identity for re-attachment in another window. The workspace is removed
    /// from both the outer tree and the workspaces HashMap.
    pub fn detach_workspace(
        &mut self,
        workspace_id: &str,
        cx: &mut Context<Self>,
    ) -> Option<(Tab, Entity<SplitContainer>, Option<WorkspaceIdentity>)> {
        // Find the tab in the outer tree
        let (pane_id, tab_id) = self.outer_tree.find_workspace_tab(workspace_id)?;

        // Get the tab data before removing
        let tab = self
            .outer_tree
            .find_pane(pane_id)?
            .tabs
            .iter()
            .find(|t| t.id == tab_id)?
            .clone();

        // Remove from outer tree
        if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
            pane.remove_tab(tab_id);

            // If pane is now empty, close it (unless it's the last pane)
            if pane.tabs.is_empty() {
                let all_panes = self.outer_tree.all_pane_ids();
                if all_panes.len() > 1 {
                    let _ = self.outer_tree.close_pane(pane_id);
                    self.active_outer_pane = self.outer_tree.first_leaf().id;
                }
            }
        }

        // Remove the SplitContainer (but don't drop it — we're returning it)
        let container = self.workspaces.remove(workspace_id)?;
        let identity = container.read(cx).workspace_identity().cloned();

        self.save_layout(cx);
        cx.notify();
        Some((tab, container, identity))
    }

    /// Attach a workspace (previously detached from another window) into this layout.
    pub fn attach_workspace(
        &mut self,
        tab: Tab,
        container: Entity<SplitContainer>,
        identity: Option<WorkspaceIdentity>,
        cx: &mut Context<Self>,
    ) {
        let workspace_id = match &tab.content {
            TabContent::Workspace { workspace_id, .. } => workspace_id.clone(),
            _ => return,
        };

        // Store the container
        self.workspaces.insert(workspace_id, container);

        // Add the tab to the active outer pane
        if let Some(pane) = self.outer_tree.find_pane_mut(self.active_outer_pane) {
            // If the pane only has a Chat tab (default state), replace it
            if pane.tabs.len() == 1 {
                if let Some(TabContent::Chat) = pane.tabs.first().map(|t| &t.content) {
                    pane.tabs.clear();
                }
            }
            pane.add_tab(tab);
        }

        self.save_layout(cx);
        cx.notify();
    }

    /// Get the currently active workspace's SplitContainer.
    pub fn active_workspace(&self) -> Option<Entity<SplitContainer>> {
        let pane = self.outer_tree.find_pane(self.active_outer_pane)?;
        let active_tab = pane.active_tab()?;

        match &active_tab.content {
            TabContent::Workspace { workspace_id, .. } => {
                self.workspaces.get(workspace_id).cloned()
            }
            TabContent::Chat => {
                // Default state — return the default container
                self.workspaces.get("__default__").cloned()
            }
            _ => None,
        }
    }

    /// Get a workspace's SplitContainer by ID.
    pub fn workspace(&self, workspace_id: &str) -> Option<Entity<SplitContainer>> {
        self.workspaces.get(workspace_id).cloned()
    }

    /// Split at the outer (workspace) level.
    pub fn split_outer(&mut self, direction: SplitDirection, cx: &mut Context<Self>) {
        if let Some(_new_pane_id) = self.outer_tree.split(self.active_outer_pane, direction) {
            self.save_layout(cx);
            cx.notify();
        }
    }

    /// Persist this window's layout to disk (per-window file).
    fn save_layout(&self, cx: &Context<Self>) {
        let Some(ref storage) = self.layout_storage else {
            return;
        };

        let mut workspace_identities = HashMap::new();
        let mut workspace_layouts = HashMap::new();

        for (ws_id, container) in &self.workspaces {
            if ws_id == "__default__" {
                continue;
            }
            let sc = container.read(cx);
            if let Some(identity) = sc.workspace_identity() {
                workspace_identities.insert(ws_id.clone(), identity.clone());
            }
            workspace_layouts.insert(ws_id.clone(), sc.layout_state());
        }

        let state = AppLayoutState::new(
            self.outer_tree.clone(),
            self.active_outer_pane,
            workspace_identities,
            workspace_layouts,
        );

        if let Err(e) = storage.save_window_layout(&self.window_id, &state) {
            tracing::warn!("Failed to save window layout: {}", e);
        }
    }

    /// Focus an outer pane by index.
    pub fn focus_outer_pane_by_index(&mut self, index: usize, cx: &mut Context<Self>) {
        let pane_ids = self.outer_tree.all_pane_ids();
        if let Some(&pane_id) = pane_ids.get(index) {
            self.active_outer_pane = pane_id;
            cx.notify();
        }
    }

    /// Handle dropping a workspace tab onto an outer pane.
    /// Supports both same-window and cross-window drops.
    fn drop_workspace_tab(
        &mut self,
        drag_data: WorkspaceTabDragData,
        target_pane_id: PaneId,
        cx: &mut Context<Self>,
    ) {
        // Cross-window drop: the tab came from a different window
        if drag_data.source_window_id.0 != self.window_id.0 {
            // Extract workspace_id from the tab
            let workspace_id = match &drag_data.tab.content {
                TabContent::Workspace { workspace_id, .. } => workspace_id.clone(),
                _ => return,
            };

            // Find the target window index in AppState to dispatch the action
            let windows = &cx.global::<AppState>().windows;
            let target_index = windows
                .iter()
                .position(|(wid, _)| wid.0 == self.window_id.0);

            if let Some(target_index) = target_index {
                let action = MoveWorkspaceToWindow {
                    target_window_index: target_index,
                    workspace_id,
                };
                cx.dispatch_action(&action);
            }
            return;
        }

        // Same-window drop: move tab between panes
        if drag_data.source_pane_id == target_pane_id {
            return;
        }

        let tab_id = drag_data.tab.id;

        // Remove tab from source pane
        if let Some(source_pane) = self.outer_tree.find_pane_mut(drag_data.source_pane_id) {
            source_pane.remove_tab(tab_id);

            // If source pane is now empty and not the last pane, close it
            if source_pane.tabs.is_empty() {
                let all_panes = self.outer_tree.all_pane_ids();
                if all_panes.len() > 1 {
                    let _ = self.outer_tree.close_pane(drag_data.source_pane_id);
                }
            }
        }

        // Add tab to target pane
        if let Some(target_pane) = self.outer_tree.find_pane_mut(target_pane_id) {
            target_pane.add_tab(drag_data.tab);
        }

        // Set active outer pane
        self.active_outer_pane = target_pane_id;
        self.save_layout(cx);
        cx.notify();
    }

    /// Close all workspace tabs in a pane except the specified one
    fn close_other_workspace_tabs(
        &mut self,
        pane_id: PaneId,
        keep_tab_id: TabId,
        cx: &mut Context<Self>,
    ) {
        let tabs_to_close: Vec<(TabId, Option<String>)> = if let Some(pane) =
            self.outer_tree.find_pane(pane_id)
        {
            pane.tabs
                .iter()
                .filter(|t| t.id != keep_tab_id)
                .map(|t| {
                    let ws_id = match &t.content {
                        TabContent::Workspace { workspace_id, .. } => Some(workspace_id.clone()),
                        _ => None,
                    };
                    (t.id, ws_id)
                })
                .collect()
        } else {
            return;
        };

        for (tid, ws_id) in &tabs_to_close {
            if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
                pane.remove_tab(*tid);
            }
            if let Some(ws) = ws_id {
                self.workspaces.remove(ws);
            }
        }

        cx.notify();
    }

    /// Close workspace tabs to the right of the specified tab
    fn close_workspace_tabs_to_right(
        &mut self,
        pane_id: PaneId,
        tab_id: TabId,
        cx: &mut Context<Self>,
    ) {
        let tabs_to_close: Vec<(TabId, Option<String>)> =
            if let Some(pane) = self.outer_tree.find_pane(pane_id) {
                if let Some(idx) = pane.tabs.iter().position(|t| t.id == tab_id) {
                    pane.tabs[idx + 1..]
                        .iter()
                        .map(|t| {
                            let ws_id = match &t.content {
                                TabContent::Workspace { workspace_id, .. } => {
                                    Some(workspace_id.clone())
                                }
                                _ => None,
                            };
                            (t.id, ws_id)
                        })
                        .collect()
                } else {
                    return;
                }
            } else {
                return;
            };

        for (tid, ws_id) in &tabs_to_close {
            if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
                pane.remove_tab(*tid);
            }
            if let Some(ws) = ws_id {
                self.workspaces.remove(ws);
            }
        }

        cx.notify();
    }

    /// Close workspace tabs to the left of the specified tab
    fn close_workspace_tabs_to_left(
        &mut self,
        pane_id: PaneId,
        tab_id: TabId,
        cx: &mut Context<Self>,
    ) {
        let tabs_to_close: Vec<(TabId, Option<String>)> =
            if let Some(pane) = self.outer_tree.find_pane(pane_id) {
                if let Some(idx) = pane.tabs.iter().position(|t| t.id == tab_id) {
                    pane.tabs[..idx]
                        .iter()
                        .map(|t| {
                            let ws_id = match &t.content {
                                TabContent::Workspace { workspace_id, .. } => {
                                    Some(workspace_id.clone())
                                }
                                _ => None,
                            };
                            (t.id, ws_id)
                        })
                        .collect()
                } else {
                    return;
                }
            } else {
                return;
            };

        for (tid, ws_id) in &tabs_to_close {
            if let Some(pane) = self.outer_tree.find_pane_mut(pane_id) {
                pane.remove_tab(*tid);
            }
            if let Some(ws) = ws_id {
                self.workspaces.remove(ws);
            }
        }

        cx.notify();
    }

    // --- Rendering ---

    /// Render the outer pane tree.
    fn render_outer_tree(&self, node: &PaneNode, cx: &mut Context<Self>) -> gpui::AnyElement {
        match node {
            PaneNode::Split {
                id,
                direction,
                children,
                ratio,
            } => self.render_outer_split(*id, *direction, children, *ratio, cx),
            PaneNode::Leaf(leaf) => self.render_outer_pane(leaf, cx),
        }
    }

    /// Render an outer split node.
    fn render_outer_split(
        &self,
        split_id: SplitId,
        direction: SplitDirection,
        children: &[Box<PaneNode>; 2],
        ratio: f32,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let theme = Theme::dark();
        let is_horizontal = matches!(direction, SplitDirection::Horizontal);

        let first_child = self.render_outer_tree(&children[0], cx);
        let second_child = self.render_outer_tree(&children[1], cx);

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
                entity.update(cx, |this: &mut AppLayout, _cx| {
                    this.outer_split_sizes.insert(split_id, size);
                });
            })
            .id(ElementId::Name(SharedString::from(format!(
                "outer-split-{}",
                split_id.0
            ))))
            .size_full()
            .flex()
            .when(is_horizontal, |d| d.flex_row())
            .when(!is_horizontal, |d| d.flex_col());

        let first = div()
            .when(is_horizontal, |d| d.w(gpui::relative(ratio)).h_full())
            .when(!is_horizontal, |d| d.h(gpui::relative(ratio)).w_full())
            .overflow_hidden()
            .child(first_child);

        let divider = div()
            .id(ElementId::Name(SharedString::from(format!(
                "outer-divider-{}",
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
                    this.outer_divider_drag = Some(OuterDividerDrag {
                        split_id,
                        direction,
                        start_position: position,
                        start_ratio: ratio,
                        container_size: this
                            .outer_split_sizes
                            .get(&split_id)
                            .copied()
                            .unwrap_or(800.0),
                    });
                    cx.notify();
                }),
            );

        let second = div().flex_1().overflow_hidden().child(second_child);

        container
            .child(first)
            .child(divider)
            .child(second)
            .on_mouse_move(
                cx.listener(move |this, event: &MouseMoveEvent, _window, cx| {
                    if let Some(drag) = &mut this.outer_divider_drag {
                        if drag.split_id == split_id {
                            let current_position: f32 = if is_horizontal {
                                event.position.x.into()
                            } else {
                                event.position.y.into()
                            };

                            let ratio_delta =
                                (current_position - drag.start_position) / drag.container_size;
                            let new_ratio = (drag.start_ratio + ratio_delta).clamp(0.1, 0.9);

                            this.outer_tree.set_ratio_by_split_id(split_id, new_ratio);
                            cx.notify();
                        }
                    }
                }),
            )
            .on_mouse_up(
                gpui::MouseButton::Left,
                cx.listener(|this, _event, _window, cx| {
                    this.outer_divider_drag = None;
                    cx.notify();
                }),
            )
            .into_any_element()
    }

    /// Render a single outer leaf pane: workspace tab bar + active workspace content.
    fn render_outer_pane(&self, leaf: &LeafPane, cx: &mut Context<Self>) -> gpui::AnyElement {
        let theme = Theme::dark();
        let pane_id = leaf.id;
        let is_active_outer = pane_id == self.active_outer_pane;

        let tabs = leaf.tabs.clone();
        let active_tab_idx = leaf.active_tab;

        // Has multiple workspace tabs? Show the workspace tab bar
        let has_workspace_tabs = tabs
            .iter()
            .any(|t| matches!(t.content, TabContent::Workspace { .. }));

        // Build workspace tab bar (taller, distinct styling)
        let workspace_tab_bar = if has_workspace_tabs {
            div()
                .id(ElementId::Name(SharedString::from(format!(
                    "ws-tab-bar-{}",
                    pane_id.0
                ))))
                .h(px(40.0))
                .flex()
                .items_center()
                .bg(theme.background)
                .font_family(".AppleSystemUIFont")
                .py(px(8.0))
                .gap(px(4.0))
                .overflow_x_scroll()
                .children(tabs.iter().enumerate().map(|(idx, tab)| {
                    let is_active_tab = idx == active_tab_idx;
                    let tab_id = tab.id;

                    let (icon, display_name, ws_id) = match &tab.content {
                        TabContent::Workspace {
                            display_name,
                            workspace_id,
                        } => {
                            let icon = if workspace_id.starts_with("local:") {
                                "local"
                            } else {
                                "remote"
                            };
                            (icon, display_name.clone(), Some(workspace_id.clone()))
                        }
                        TabContent::Chat => ("chat", "Chat".to_string(), None),
                        _ => ("", tab.title.clone(), None),
                    };
                    let ws_id_for_menu = ws_id.clone();

                    // Create drag data for workspace tab
                    let drag_data = WorkspaceTabDragData {
                        source_window_id: self.window_id.clone(),
                        source_pane_id: pane_id,
                        tab: tab.clone(),
                    };

                    let tab_fg = if is_active_tab {
                        theme.foreground
                    } else {
                        theme.muted
                    };

                    div()
                        .id(ElementId::Name(SharedString::from(format!(
                            "ws-tab-{}-{}",
                            pane_id.0, tab_id.0
                        ))))
                        .px(px(8.0))
                        .py(px(4.0))
                        .flex()
                        .flex_shrink_0()
                        .items_center()
                        .gap_2()
                        .rounded(px(8.0))
                        .bg(if is_active_tab {
                            theme.surface
                        } else {
                            gpui::hsla(0.0, 0.0, 0.0, 0.0)
                        })
                        .cursor_pointer()
                        .hover(|s| s.bg(theme.hover).rounded(px(8.0)))
                        .on_drag(drag_data, |drag_data, _event, _window, cx| {
                            cx.new(|_cx| WorkspaceTabDragPreview {
                                title: drag_data.tab.title.clone(),
                            })
                        })
                        .on_click(cx.listener(move |this, _event, _window, cx| {
                            this.context_menu = None;
                            this.active_outer_pane = pane_id;
                            if let Some(pane) = this.outer_tree.find_pane_mut(pane_id) {
                                pane.set_active_tab(tab_id);
                            }
                            cx.notify();
                        }))
                        .on_mouse_down(
                            MouseButton::Right,
                            cx.listener(move |this, event: &MouseDownEvent, _window, cx| {
                                let (tab_index, tab_count) = this
                                    .outer_tree
                                    .find_pane(pane_id)
                                    .map(|p| {
                                        let idx =
                                            p.tabs.iter().position(|t| t.id == tab_id).unwrap_or(0);
                                        (idx, p.tabs.len())
                                    })
                                    .unwrap_or((0, 0));
                                this.context_menu = Some(ContextMenu {
                                    position: event.position,
                                    pane_id,
                                    tab_id,
                                    workspace_id: ws_id_for_menu.clone(),
                                    tab_index,
                                    tab_count,
                                });
                                cx.notify();
                            }),
                        )
                        // Icon
                        .child(
                            svg()
                                .path(if icon == "local" {
                                    "icons/folder.svg"
                                } else if icon == "remote" {
                                    "icons/terminal.svg"
                                } else {
                                    "icons/symbol-misc.svg"
                                })
                                .size(px(14.0))
                                .text_color(if icon == "local" {
                                    theme.explorer_dir_icon
                                } else if icon == "remote" {
                                    theme.status_running
                                } else {
                                    theme.muted
                                }),
                        )
                        // Name
                        .child(
                            div()
                                .text_size(px(13.0))
                                .text_color(tab_fg)
                                .max_w(px(160.0))
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .child(display_name),
                        )
                        // Close button
                        .child(
                            div()
                                .id(ElementId::Name(SharedString::from(format!(
                                    "ws-tab-close-{}-{}",
                                    pane_id.0, tab_id.0
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
                                    // Find the workspace_id from the tab before closing
                                    let ws_id = this
                                        .outer_tree
                                        .find_pane(pane_id)
                                        .and_then(|p| p.tabs.iter().find(|t| t.id == tab_id))
                                        .and_then(|t| match &t.content {
                                            TabContent::Workspace { workspace_id, .. } => {
                                                Some(workspace_id.clone())
                                            }
                                            _ => None,
                                        });

                                    if let Some(ws_id) = ws_id {
                                        this.close_workspace(&ws_id, cx);
                                    }
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
                // --- Action buttons (right side) ---
                // Split right
                .child(
                    div()
                        .id(ElementId::Name(SharedString::from(format!(
                            "ws-split-h-{}",
                            pane_id.0
                        ))))
                        .w(px(28.0))
                        .h(px(28.0))
                        .mx(px(2.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(4.0))
                        .text_color(theme.muted)
                        .cursor_pointer()
                        .hover(|s| s.bg(theme.hover).text_color(theme.foreground))
                        .on_click(cx.listener(move |this, _event, _window, cx| {
                            this.active_outer_pane = pane_id;
                            this.split_outer(SplitDirection::Horizontal, cx);
                        }))
                        .child(
                            svg()
                                .path("icons/split-horizontal.svg")
                                .size(px(16.0))
                                .text_color(theme.muted),
                        ),
                )
                // Split down
                .child(
                    div()
                        .id(ElementId::Name(SharedString::from(format!(
                            "ws-split-v-{}",
                            pane_id.0
                        ))))
                        .w(px(28.0))
                        .h(px(28.0))
                        .mx(px(2.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(4.0))
                        .text_color(theme.muted)
                        .cursor_pointer()
                        .hover(|s| s.bg(theme.hover).text_color(theme.foreground))
                        .on_click(cx.listener(move |this, _event, _window, cx| {
                            this.active_outer_pane = pane_id;
                            this.split_outer(SplitDirection::Vertical, cx);
                        }))
                        .child(
                            svg()
                                .path("icons/split-vertical.svg")
                                .size(px(16.0))
                                .text_color(theme.muted),
                        ),
                )
                .child(div().w(px(8.0)))
                .into_any_element()
        } else {
            div().into_any_element()
        };

        // Render the active workspace's inner content
        let content: gpui::AnyElement = if let Some(active_tab) = tabs.get(active_tab_idx) {
            match &active_tab.content {
                TabContent::Workspace { workspace_id, .. } => {
                    if let Some(container) = self.workspaces.get(workspace_id) {
                        container.clone().into_any_element()
                    } else {
                        div()
                            .flex_1()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(theme.muted)
                            .child("Workspace not found")
                            .into_any_element()
                    }
                }
                TabContent::Chat => {
                    // Default state: render the default container
                    if let Some(container) = self.workspaces.get("__default__") {
                        container.clone().into_any_element()
                    } else {
                        self.chat_panel.clone().into_any_element()
                    }
                }
                _ => div()
                    .flex_1()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(theme.muted)
                    .child("Unknown tab type")
                    .into_any_element(),
            }
        } else {
            div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_color(theme.muted)
                .child("No workspace open")
                .into_any_element()
        };

        div()
            .id(ElementId::Name(SharedString::from(format!(
                "outer-pane-{}",
                pane_id.0
            ))))
            .size_full()
            .flex()
            .flex_col()
            .bg(theme.background)
            // Visual feedback when dragging a workspace tab over this pane
            .drag_over::<WorkspaceTabDragData>(|style, _, _window, _cx| {
                style.border_2().border_color(Theme::dark().accent)
            })
            // Handle workspace tab drops
            .on_drop(
                cx.listener(move |this, drag_data: &WorkspaceTabDragData, _window, cx| {
                    this.drop_workspace_tab(drag_data.clone(), pane_id, cx);
                }),
            )
            .on_click(cx.listener(move |this, _event, _window, cx| {
                this.active_outer_pane = pane_id;
                cx.notify();
            }))
            .child(workspace_tab_bar)
            .child(div().flex_1().overflow_hidden().p(px(4.0)).child(content))
            .into_any_element()
    }
}

impl Focusable for AppLayout {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl AppLayout {
    fn render_context_menu(&self, menu: &ContextMenu, cx: &mut Context<Self>) -> gpui::AnyElement {
        let theme = Theme::dark();
        let pos = menu.position;
        let pane_id = menu.pane_id;
        let tab_id = menu.tab_id;
        let tab_index = menu.tab_index;
        let tab_count = menu.tab_count;
        let ws_id = menu.workspace_id.clone();
        let ws_id_close = ws_id.clone();

        // Dismiss overlay — uses on_click (not on_mouse_down) so it doesn't
        // steal the pending mouse-down from menu items' on_click handlers.
        let dismiss = div()
            .id("ws-ctx-dismiss")
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

        // Menu items
        let mut menu_panel = div()
            .w(px(200.0))
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .rounded(px(6.0))
            .py(px(4.0))
            .shadow_lg()
            // Close Workspace (if tab is a workspace)
            .when(ws_id_close.is_some(), |d| {
                let ws = ws_id_close.clone().unwrap();
                d.child(
                    item_style("ws-ctx-close", "Close Workspace").on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_workspace(&ws, cx);
                        },
                    )),
                )
            })
            // Close Other Tabs (if >1 tab)
            .when(tab_count > 1, |d| {
                d.child(
                    item_style("ws-ctx-close-others", "Close Other Tabs").on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_other_workspace_tabs(pane_id, tab_id, cx);
                        },
                    )),
                )
            })
            // Close Tabs to the Right (if not last tab)
            .when(tab_index + 1 < tab_count, |d| {
                d.child(
                    item_style("ws-ctx-close-right", "Close Tabs to the Right").on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_workspace_tabs_to_right(pane_id, tab_id, cx);
                        }),
                    ),
                )
            })
            // Close Tabs to the Left (if not first tab)
            .when(tab_index > 0, |d| {
                d.child(
                    item_style("ws-ctx-close-left", "Close Tabs to the Left").on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.context_menu = None;
                            this.close_workspace_tabs_to_left(pane_id, tab_id, cx);
                        }),
                    ),
                )
            })
            // Separator
            .child(separator())
            // Split Right
            .child(
                item_style("ws-ctx-split-h", "Split Right").on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        this.active_outer_pane = pane_id;
                        this.split_outer(SplitDirection::Horizontal, cx);
                    },
                )),
            )
            // Split Down
            .child(
                item_style("ws-ctx-split-v", "Split Down").on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        this.active_outer_pane = pane_id;
                        this.split_outer(SplitDirection::Vertical, cx);
                    },
                )),
            );

        // "Move to Window..." — only shown when there are multiple windows and tab is a workspace
        let window_count = cx.global::<AppState>().windows.len();
        if ws_id.is_some() && window_count > 1 {
            let self_window_id = self.window_id.clone();
            menu_panel = menu_panel.child(separator());

            let windows = &cx.global::<AppState>().windows;
            for (i, (wid, _)) in windows.iter().enumerate() {
                if wid.0 == self_window_id.0 {
                    continue; // Skip this window
                }
                let target_index = i;
                let ws_id_move = ws_id.clone().unwrap();
                let label: SharedString = format!("Move to Window {}", i + 1).into();
                let item_id = format!("ws-ctx-move-to-{}", i);
                menu_panel = menu_panel.child(item_style(&item_id, &label).on_click(cx.listener(
                    move |this, _, _, cx| {
                        this.context_menu = None;
                        let action = MoveWorkspaceToWindow {
                            target_window_index: target_index,
                            workspace_id: ws_id_move.clone(),
                        };
                        cx.dispatch_action(&action);
                    },
                )));
            }
        }

        div()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .child(dismiss)
            .child(anchored().position(pos).snap_to_window().child(menu_panel))
            .into_any_element()
    }
}

impl Render for AppLayout {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        let mut root = div()
            .relative()
            .size_full()
            .bg(theme.background)
            .track_focus(&self.focus_handle(cx))
            .child(self.render_outer_tree(&self.outer_tree.clone(), cx));

        if let Some(menu) = self.context_menu.clone() {
            root = root.child(self.render_context_menu(&menu, cx));
        }

        root
    }
}
