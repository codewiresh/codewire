//! File browser (Explorer) component with lazy-loaded directory tree.
//!
//! Layout: controls bar + search bar + file tree (uniform_list)
//! Uses gpui's uniform_list for virtualized rendering of file rows.

use crate::input::TextInput;
use crate::theme::Theme;
use codewire_ui::icon_button;
use gpui::{
    App, Context, ElementId, Entity, EventEmitter, FocusHandle, Focusable, ScrollStrategy,
    SharedString, UniformListScrollHandle, Window, actions, div, prelude::*, px, svg, uniform_list,
};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

actions!(
    explorer,
    [
        NextExplorerItem,
        PrevExplorerItem,
        ToggleOrOpen,
        RefreshExplorer
    ]
);

// ── Types ────────────────────────────────────────────────────────────────

/// Source of file data.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum FileSource {
    /// Local directory on disk
    Local { root_path: String },
}

impl FileSource {
    /// Unique key for tab deduplication and entity caching
    pub fn source_id(&self) -> String {
        match self {
            FileSource::Local { root_path } => format!("explorer-local:{}", root_path),
        }
    }

    /// Display name for tab title
    pub fn display_name(&self) -> String {
        match self {
            FileSource::Local { root_path } => std::path::Path::new(root_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(root_path)
                .to_string(),
        }
    }
}

/// Type of filesystem entry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileEntryType {
    File,
    Directory,
    Symlink,
}

/// Git status for a file
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileGitStatus {
    Modified,
    Added,
    Deleted,
    Untracked,
    Renamed,
}

/// Load state for a directory node
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadState {
    NotLoaded,
    Loading,
    Loaded,
    Error(String),
}

/// A node in the file tree
#[derive(Clone, Debug)]
pub struct FileNode {
    pub name: String,
    pub relative_path: String,
    pub entry_type: FileEntryType,
    pub size: u64,
    pub git_status: Option<FileGitStatus>,
    pub children: Option<Vec<usize>>, // indices into all_nodes
    pub load_state: LoadState,
}

/// Row in the flattened virtual list. Copy because it's just indices.
#[derive(Clone, Copy)]
enum FlatRow {
    Directory { node_idx: usize, depth: usize },
    File { node_idx: usize, depth: usize },
    Loading { depth: usize },
}

/// Fixed row height for uniform_list
const ROW_HEIGHT: f32 = 28.0;

/// Event emitted when a file is selected (clicked)
#[derive(Clone, Debug)]
pub struct FileSelected {
    pub path: String,
    pub source: FileSource,
}

// ── FileExplorer ─────────────────────────────────────────────────────────

pub struct FileExplorer {
    source: FileSource,
    /// All nodes in a flat pool, indexed by usize
    all_nodes: Vec<FileNode>,
    /// Indices of root-level nodes in all_nodes
    root_node_indices: Vec<usize>,
    /// Set of relative_path for expanded directories
    expanded_dirs: HashSet<String>,
    /// Flattened rows for the virtual list
    flat_rows: Vec<FlatRow>,
    scroll_handle: UniformListScrollHandle,
    /// Currently selected file path
    selected_path: Option<String>,
    /// Index of the currently selected flat row (for keyboard nav)
    selected_row_idx: Option<usize>,
    search_input: Entity<TextInput>,
    search_term: String,
    focus_handle: FocusHandle,
}

impl EventEmitter<FileSelected> for FileExplorer {}

impl FileExplorer {
    pub fn new(source: FileSource, cx: &mut Context<Self>) -> Self {
        let search_input = cx.new(|cx| TextInput::new("Filter files...", cx));

        // Watch search input for changes
        cx.observe(&search_input, |this: &mut Self, input, cx| {
            let new_term = input.read(cx).content().to_string();
            if new_term != this.search_term {
                this.search_term = new_term;
                this.rebuild_flat_rows();
                cx.notify();
            }
        })
        .detach();

        let mut explorer = Self {
            source: source.clone(),
            all_nodes: Vec::new(),
            root_node_indices: Vec::new(),
            expanded_dirs: HashSet::new(),
            flat_rows: Vec::new(),
            scroll_handle: UniformListScrollHandle::new(),
            selected_path: None,
            selected_row_idx: None,
            search_input,
            search_term: String::new(),
            focus_handle: cx.focus_handle(),
        };

        // Start loading root directory
        explorer.spawn_load_directory(String::new(), cx);

        explorer
    }

    // ── Directory loading ────────────────────────────────────────────────

    fn spawn_load_directory(&mut self, relative_path: String, cx: &mut Context<Self>) {
        let source = self.source.clone();

        cx.spawn(async move |this, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();
            let rel_path = relative_path.clone();

            let FileSource::Local { root_path } = source;
            std::thread::spawn(move || {
                let full_path = if rel_path.is_empty() {
                    root_path.clone()
                } else {
                    format!("{}/{}", root_path, rel_path)
                };
                let result = read_local_directory(&full_path, &rel_path);
                let _ = tx.send(result);
            });

            let result = rx.await;

            match result {
                Ok(Ok(entries)) => {
                    let is_root = relative_path.is_empty();
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.insert_children(&relative_path, entries);
                            view.rebuild_flat_rows();
                            // Load git status after root directory loads
                            if is_root {
                                view.spawn_load_git_status(cx);
                            }
                            cx.notify();
                        });
                    });
                }
                Ok(Err(e)) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.set_dir_error(&relative_path, e);
                            view.rebuild_flat_rows();
                            cx.notify();
                        });
                    });
                }
                Err(_) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.set_dir_error(&relative_path, "Load cancelled".into());
                            view.rebuild_flat_rows();
                            cx.notify();
                        });
                    });
                }
            }
        })
        .detach();
    }

    /// Insert loaded children into the node pool
    fn insert_children(&mut self, parent_path: &str, entries: Vec<FileNode>) {
        let child_indices: Vec<usize> = entries
            .into_iter()
            .map(|node| {
                let idx = self.all_nodes.len();
                self.all_nodes.push(node);
                idx
            })
            .collect();

        if parent_path.is_empty() {
            // Root level
            self.root_node_indices = child_indices;
        } else {
            // Find parent node and set children
            if let Some(parent) = self
                .all_nodes
                .iter_mut()
                .find(|n| n.relative_path == parent_path)
            {
                parent.children = Some(child_indices);
                parent.load_state = LoadState::Loaded;
            }
        }
    }

    fn set_dir_error(&mut self, dir_path: &str, error: String) {
        if dir_path.is_empty() {
            return;
        }
        if let Some(node) = self
            .all_nodes
            .iter_mut()
            .find(|n| n.relative_path == dir_path)
        {
            node.load_state = LoadState::Error(error);
        }
    }

    // ── Flat row management ──────────────────────────────────────────────

    fn rebuild_flat_rows(&mut self) {
        self.flat_rows.clear();
        let root_indices = self.root_node_indices.clone();
        for &idx in &root_indices {
            self.flatten_node(idx, 0);
        }
    }

    fn flatten_node(&mut self, node_idx: usize, depth: usize) {
        let node = &self.all_nodes[node_idx];

        // Apply search filter
        if !self.search_term.is_empty() {
            let term = self.search_term.to_lowercase();
            let name_match = node.name.to_lowercase().contains(&term);

            if node.entry_type == FileEntryType::Directory {
                // For directories, check if any descendant matches
                let has_matching_children = self.has_matching_descendant(node_idx, &term);
                if !name_match && !has_matching_children {
                    return;
                }
            } else if !name_match {
                return;
            }
        }

        match node.entry_type {
            FileEntryType::Directory => {
                self.flat_rows.push(FlatRow::Directory { node_idx, depth });

                let rel_path = node.relative_path.clone();
                let load_state = node.load_state.clone();
                let children = node.children.clone();

                if self.expanded_dirs.contains(&rel_path) {
                    match load_state {
                        LoadState::NotLoaded | LoadState::Loading => {
                            self.flat_rows.push(FlatRow::Loading { depth: depth + 1 });
                        }
                        LoadState::Loaded => {
                            if let Some(child_indices) = children {
                                for &child_idx in &child_indices {
                                    self.flatten_node(child_idx, depth + 1);
                                }
                            }
                        }
                        LoadState::Error(_) => {
                            // Show nothing for errored directories (could add error row later)
                        }
                    }
                }
            }
            FileEntryType::File | FileEntryType::Symlink => {
                self.flat_rows.push(FlatRow::File { node_idx, depth });
            }
        }
    }

    fn has_matching_descendant(&self, node_idx: usize, term: &str) -> bool {
        let node = &self.all_nodes[node_idx];
        if let Some(ref children) = node.children {
            for &child_idx in children {
                let child = &self.all_nodes[child_idx];
                if child.name.to_lowercase().contains(term) {
                    return true;
                }
                if child.entry_type == FileEntryType::Directory
                    && self.has_matching_descendant(child_idx, term)
                {
                    return true;
                }
            }
        }
        false
    }

    // ── Interaction ──────────────────────────────────────────────────────

    fn toggle_directory(&mut self, node_idx: usize, cx: &mut Context<Self>) {
        let node = &self.all_nodes[node_idx];
        let path = node.relative_path.clone();
        let load_state = node.load_state.clone();

        if self.expanded_dirs.contains(&path) {
            self.expanded_dirs.remove(&path);
        } else {
            self.expanded_dirs.insert(path.clone());

            // Trigger lazy load if not yet loaded
            if load_state == LoadState::NotLoaded {
                if let Some(node) = self.all_nodes.get_mut(node_idx) {
                    node.load_state = LoadState::Loading;
                }
                self.spawn_load_directory(path, cx);
            }
        }

        self.rebuild_flat_rows();
        cx.notify();
    }

    fn select_file(&mut self, node_idx: usize, cx: &mut Context<Self>) {
        let node = &self.all_nodes[node_idx];
        let path = node.relative_path.clone();
        self.selected_path = Some(path.clone());

        cx.emit(FileSelected {
            path,
            source: self.source.clone(),
        });
        cx.notify();
    }

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.all_nodes.clear();
        self.root_node_indices.clear();
        self.expanded_dirs.clear();
        self.flat_rows.clear();
        self.selected_path = None;
        self.selected_row_idx = None;
        cx.notify();
        self.spawn_load_directory(String::new(), cx);
    }

    // ── Keyboard navigation ─────────────────────────────────────────────

    fn next_item(&mut self, _: &NextExplorerItem, _window: &mut Window, cx: &mut Context<Self>) {
        if self.flat_rows.is_empty() {
            return;
        }
        let next = match self.selected_row_idx {
            None => 0,
            Some(idx) => (idx + 1).min(self.flat_rows.len() - 1),
        };
        self.selected_row_idx = Some(next);
        self.scroll_handle
            .scroll_to_item(next, ScrollStrategy::Center);
        cx.notify();
    }

    fn prev_item(&mut self, _: &PrevExplorerItem, _window: &mut Window, cx: &mut Context<Self>) {
        if self.flat_rows.is_empty() {
            return;
        }
        let prev = match self.selected_row_idx {
            None => 0,
            Some(idx) => idx.saturating_sub(1),
        };
        self.selected_row_idx = Some(prev);
        self.scroll_handle
            .scroll_to_item(prev, ScrollStrategy::Center);
        cx.notify();
    }

    fn toggle_or_open(&mut self, _: &ToggleOrOpen, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(idx) = self.selected_row_idx else {
            return;
        };
        if idx >= self.flat_rows.len() {
            return;
        }
        match self.flat_rows[idx] {
            FlatRow::Directory { node_idx, .. } => {
                self.toggle_directory(node_idx, cx);
            }
            FlatRow::File { node_idx, .. } => {
                self.select_file(node_idx, cx);
            }
            FlatRow::Loading { .. } => {}
        }
    }

    fn refresh_action(
        &mut self,
        _: &RefreshExplorer,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.refresh(cx);
    }

    // ── Git status ──────────────────────────────────────────────────────

    fn spawn_load_git_status(&mut self, cx: &mut Context<Self>) {
        let source = self.source.clone();

        cx.spawn(async move |this, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();

            let FileSource::Local { root_path } = source;
            std::thread::spawn(move || {
                let result = run_git_status_local(&root_path);
                let _ = tx.send(result);
            });

            if let Ok(Ok(statuses)) = rx.await {
                cx.update(|cx| {
                    let _ = this.update(cx, |view, cx| {
                        view.apply_git_statuses(statuses);
                        view.rebuild_flat_rows();
                        cx.notify();
                    });
                });
            }
        })
        .detach();
    }

    fn apply_git_statuses(&mut self, statuses: HashMap<String, FileGitStatus>) {
        for node in &mut self.all_nodes {
            if let Some(status) = statuses.get(&node.relative_path) {
                node.git_status = Some(*status);
            }
        }
    }

    // ── Render ───────────────────────────────────────────────────────────

    fn render_controls(&self, theme: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        let display_name = self.source.display_name();

        div()
            .h(px(36.0))
            .flex()
            .items_center()
            .px_2()
            .gap_1()
            .border_b_1()
            .border_color(theme.border)
            .bg(theme.diff_controls_bg)
            .text_size(px(11.0))
            // Path breadcrumb
            .child(
                div()
                    .flex_1()
                    .text_color(theme.foreground)
                    .font_weight(gpui::FontWeight::MEDIUM)
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .child(display_name),
            )
            // Refresh button
            .child(
                icon_button("icons/refresh.svg", 14.0, theme.muted, theme)
                    .id("explorer-refresh")
                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
            )
            .into_any_element()
    }

    fn render_search_bar(&self, theme: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        div()
            .h(px(32.0))
            .flex()
            .items_center()
            .px_3()
            .gap_2()
            .border_b_1()
            .border_color(theme.border)
            .key_context("TextInput")
            .child(
                svg()
                    .path("icons/search.svg")
                    .size(px(13.0))
                    .text_color(theme.muted),
            )
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.0))
                    .child(self.search_input.clone()),
            )
            .when(!self.search_term.is_empty(), |el| {
                el.child(
                    icon_button("icons/close.svg", 12.0, theme.muted, theme)
                        .id("explorer-search-clear")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.search_input.update(cx, |input, cx| input.clear(cx));
                        })),
                )
            })
            .into_any_element()
    }

    fn render_flat_row(
        &self,
        idx: usize,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let row = self.flat_rows[idx];
        match row {
            FlatRow::Directory { node_idx, depth } => {
                self.render_directory_row(node_idx, depth, idx, theme, cx)
            }
            FlatRow::File { node_idx, depth } => {
                self.render_file_row(node_idx, depth, idx, theme, cx)
            }
            FlatRow::Loading { depth } => self.render_loading_row(depth, theme),
        }
    }

    fn render_directory_row(
        &self,
        node_idx: usize,
        depth: usize,
        row_idx: usize,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let node = &self.all_nodes[node_idx];
        let name = node.name.clone();
        let rel_path = node.relative_path.clone();
        let is_expanded = self.expanded_dirs.contains(&rel_path);
        let is_selected = self.selected_row_idx == Some(row_idx);
        let indent = depth as f32 * 16.0;

        div()
            .id(ElementId::Name(SharedString::from(format!(
                "dir-{}",
                node_idx
            ))))
            .h(px(ROW_HEIGHT))
            .w_full()
            .flex()
            .items_center()
            .pl(px(8.0 + indent))
            .pr(px(8.0))
            .gap_1()
            .cursor_pointer()
            .bg(if is_selected {
                theme.explorer_selected_bg
            } else {
                gpui::hsla(0.0, 0.0, 0.0, 0.0)
            })
            .hover_style(|s| s.bg(theme.hover))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected_row_idx = Some(row_idx);
                this.toggle_directory(node_idx, cx);
            }))
            // Chevron
            .child(
                svg()
                    .path(if is_expanded {
                        "icons/chevron-down.svg"
                    } else {
                        "icons/chevron-right.svg"
                    })
                    .size(px(14.0))
                    .text_color(theme.muted),
            )
            // Folder icon
            .child(
                svg()
                    .path(if is_expanded {
                        "icons/folder-opened.svg"
                    } else {
                        "icons/folder.svg"
                    })
                    .size(px(14.0))
                    .text_color(theme.explorer_dir_icon),
            )
            // Name
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.0))
                    .text_color(theme.foreground)
                    .font_family("Menlo")
                    .overflow_hidden()
                    .child(name),
            )
            .into_any_element()
    }

    fn render_file_row(
        &self,
        node_idx: usize,
        depth: usize,
        row_idx: usize,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let node = &self.all_nodes[node_idx];
        let name = node.name.clone();
        let is_selected_file = self.selected_path.as_deref() == Some(&node.relative_path);
        let is_selected_row = self.selected_row_idx == Some(row_idx);
        let indent = depth as f32 * 16.0;
        let git_status = node.git_status;

        // File type indicator based on extension (kept as text for compactness)
        let ext = std::path::Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let type_indicator: Option<&str> = match ext {
            "rs" => Some("R"),
            "ts" | "tsx" => Some("T"),
            "js" | "jsx" => Some("J"),
            "py" => Some("P"),
            "go" => Some("G"),
            "md" => Some("M"),
            "toml" | "yaml" | "yml" | "json" => Some("C"),
            "html" => Some("H"),
            "css" | "scss" => Some("S"),
            _ => None,
        };

        let bg = if is_selected_file || is_selected_row {
            theme.explorer_selected_bg
        } else {
            gpui::hsla(0.0, 0.0, 0.0, 0.0)
        };

        let mut row = div()
            .id(ElementId::Name(SharedString::from(format!(
                "file-{}",
                node_idx
            ))))
            .h(px(ROW_HEIGHT))
            .w_full()
            .flex()
            .items_center()
            .pl(px(8.0 + indent))
            .pr(px(8.0))
            .gap_1()
            .cursor_pointer()
            .bg(bg)
            .hover_style(|s| s.bg(theme.hover))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected_row_idx = Some(row_idx);
                this.select_file(node_idx, cx);
            }))
            // Type indicator
            .child(if let Some(indicator) = type_indicator {
                div()
                    .w(px(14.0))
                    .text_size(px(10.0))
                    .text_color(theme.explorer_file_icon)
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(indicator)
                    .into_any_element()
            } else {
                svg()
                    .path("icons/file.svg")
                    .size(px(14.0))
                    .text_color(theme.explorer_file_icon)
                    .into_any_element()
            })
            // Name
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.0))
                    .text_color(theme.foreground)
                    .font_family("Menlo")
                    .overflow_hidden()
                    .child(name),
            );

        // Git status badge
        if let Some(status) = git_status {
            let (badge_text, badge_color) = match status {
                FileGitStatus::Modified => ("M", theme.diff_badge_modified),
                FileGitStatus::Added => ("A", theme.diff_badge_added),
                FileGitStatus::Deleted => ("D", theme.diff_badge_deleted),
                FileGitStatus::Untracked => ("U", theme.accent),
                FileGitStatus::Renamed => ("R", theme.diff_badge_renamed),
            };
            row = row.child(
                div()
                    .text_size(px(9.0))
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_color(badge_color)
                    .child(badge_text),
            );
        }

        row.into_any_element()
    }

    fn render_loading_row(&self, depth: usize, theme: &Theme) -> gpui::AnyElement {
        let indent = depth as f32 * 16.0;

        div()
            .h(px(ROW_HEIGHT))
            .w_full()
            .flex()
            .items_center()
            .pl(px(8.0 + indent))
            .text_size(px(11.0))
            .text_color(theme.muted)
            .child("Loading...")
            .into_any_element()
    }
}

// ── Trait impls ──────────────────────────────────────────────────────────

impl Focusable for FileExplorer {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for FileExplorer {
    #[allow(refining_impl_trait)]
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> gpui::AnyElement {
        let theme = Theme::dark();

        if self.root_node_indices.is_empty() && self.all_nodes.is_empty() {
            // Loading state
            return div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(theme.muted)
                .text_size(px(13.0))
                .child(format!("Loading {}...", self.source.display_name()))
                .into_any_element();
        }

        let theme_for_list = theme;

        let mut container = div()
            .size_full()
            .flex()
            .flex_col()
            .bg(theme.surface)
            .key_context("ExplorerView")
            .track_focus(&self.focus_handle(cx))
            .on_action(cx.listener(Self::next_item))
            .on_action(cx.listener(Self::prev_item))
            .on_action(cx.listener(Self::toggle_or_open))
            .on_action(cx.listener(Self::refresh_action));

        container = container.child(self.render_controls(&theme, cx));
        container = container.child(self.render_search_bar(&theme, cx));

        if self.flat_rows.is_empty() && !self.search_term.is_empty() {
            container = container.child(
                div()
                    .flex_1()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(theme.muted)
                    .text_size(px(13.0))
                    .child("No files match search"),
            );
        } else {
            container = container.child(
                uniform_list(
                    "file-list",
                    self.flat_rows.len(),
                    cx.processor(move |this, range: Range<usize>, _win, cx| {
                        let mut items = Vec::with_capacity(range.end - range.start);
                        for i in range {
                            items.push(this.render_flat_row(i, &theme_for_list, cx));
                        }
                        items
                    }),
                )
                .flex_1()
                .track_scroll(&self.scroll_handle),
            );
        }

        container.into_any_element()
    }
}

// ── Local directory reading ──────────────────────────────────────────────

fn read_local_directory(full_path: &str, relative_prefix: &str) -> Result<Vec<FileNode>, String> {
    let entries =
        std::fs::read_dir(full_path).map_err(|e| format!("Failed to read directory: {}", e))?;

    let mut nodes: Vec<FileNode> = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files by default
        if name.starts_with('.') {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let entry_type = if metadata.is_dir() {
            FileEntryType::Directory
        } else if metadata.file_type().is_symlink() {
            FileEntryType::Symlink
        } else {
            FileEntryType::File
        };

        let relative_path = if relative_prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", relative_prefix, name)
        };

        nodes.push(FileNode {
            name,
            relative_path,
            entry_type,
            size: metadata.len(),
            git_status: None,
            children: None,
            load_state: if entry_type == FileEntryType::Directory {
                LoadState::NotLoaded
            } else {
                LoadState::Loaded
            },
        });
    }

    // Sort: directories first, then alphabetical (case-insensitive)
    nodes.sort_by(|a, b| {
        let a_is_dir = a.entry_type == FileEntryType::Directory;
        let b_is_dir = b.entry_type == FileEntryType::Directory;
        match (a_is_dir, b_is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        }
    });

    Ok(nodes)
}

// ── Git status helpers ──────────────────────────────────────────────────

fn parse_git_status_porcelain(output: &str) -> HashMap<String, FileGitStatus> {
    let mut statuses = HashMap::new();

    for line in output.lines() {
        if line.len() < 4 {
            continue;
        }
        let status_code = &line[..2];
        let file_path = line[3..].trim();

        // Handle renames: "R  old -> new"
        let path = if let Some(arrow_pos) = file_path.find(" -> ") {
            &file_path[arrow_pos + 4..]
        } else {
            file_path
        };

        let git_status = match status_code.trim() {
            "M" | "MM" | "AM" => FileGitStatus::Modified,
            "A" => FileGitStatus::Added,
            "D" => FileGitStatus::Deleted,
            "R" | "RM" => FileGitStatus::Renamed,
            "??" => FileGitStatus::Untracked,
            _ => continue,
        };

        statuses.insert(path.to_string(), git_status);
    }

    statuses
}

fn run_git_status_local(root_path: &str) -> Result<HashMap<String, FileGitStatus>, String> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root_path)
        .output()
        .map_err(|e| format!("Failed to run git status: {}", e))?;

    if !output.status.success() {
        return Ok(HashMap::new()); // Not a git repo, that's fine
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_git_status_porcelain(&stdout))
}

#[cfg(test)]
mod tests {
    use super::FileSource;

    #[test]
    fn retired_ssh_file_source_is_rejected() {
        let retired = r#"{"Ssh":{"ssh_host":"example.invalid","root_path":"/workspace"}}"#;
        assert!(serde_json::from_str::<FileSource>(retired).is_err());
    }
}
