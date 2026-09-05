//! Mux-style unified diff viewer component
//!
//! Layout: controls bar + search bar + (file tree | virtual hunk list)
//! Uses gpui's uniform_list for virtualized rendering of diff lines.

use crate::input::TextInput;
use crate::local_diff::{self, DiffSource};
use crate::theme::Theme;
use crate::{FocusDiffSearch, NextDiffFile, PrevDiffFile, RefreshDiff, ToggleDiffFile};
use codewire_types::{DiffLine, DiffLineType, FileChangeType, FileDiff};
use codewire_ui::icon_button;
use gpui::{
    App, Context, ElementId, Entity, FocusHandle, Focusable, ScrollStrategy, SharedString,
    UniformListScrollHandle, Window, div, prelude::*, px, svg, uniform_list,
};
use std::collections::HashSet;
use std::ops::Range;

// ── Types ────────────────────────────────────────────────────────────────

enum DiffStatus {
    Loading,
    Loaded,
    Error(String),
}

/// Row in the flattened virtual list. Copy because it's just indices.
#[derive(Clone, Copy)]
enum FlatRow {
    FileHeader {
        file_idx: usize,
    },
    DiffLine {
        file_idx: usize,
        hunk_idx: usize,
        line_idx: usize,
    },
}

/// Fixed row height for uniform_list (all rows are exactly this height).
const ROW_HEIGHT: f32 = 22.0;

// ── DiffView ─────────────────────────────────────────────────────────────

pub struct DiffView {
    source: DiffSource,
    status: DiffStatus,
    files: Vec<FileDiff>,

    // Virtual list
    flat_rows: Vec<FlatRow>,
    scroll_handle: UniformListScrollHandle,

    // UI state
    expanded_files: HashSet<String>,
    selected_file_filter: Option<String>,
    /// Index of the currently keyboard-selected file in the filtered file list
    selected_file_idx: Option<usize>,
    search_input: Entity<TextInput>,
    search_term: String,
    show_uncommitted: bool,
    focus_handle: FocusHandle,
}

impl DiffView {
    pub fn new(source: DiffSource, cx: &mut Context<Self>) -> Self {
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

        let view = Self {
            source: source.clone(),
            status: DiffStatus::Loading,
            files: Vec::new(),
            flat_rows: Vec::new(),
            scroll_handle: UniformListScrollHandle::new(),
            expanded_files: HashSet::new(),
            selected_file_filter: None,
            selected_file_idx: None,
            search_input,
            search_term: String::new(),
            show_uncommitted: false,
            focus_handle: cx.focus_handle(),
        };

        Self::spawn_discovery(source, false, cx);
        view
    }

    // ── Discovery ────────────────────────────────────────────────────────

    fn spawn_discovery(source: DiffSource, uncommitted: bool, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();

            let DiffSource::Local { path } = source;
            std::thread::spawn(move || {
                let result = if uncommitted {
                    local_diff::discover_local_diff_uncommitted(&path)
                } else {
                    local_diff::discover_local_diff(&path)
                }
                .map(|result| result.files);
                let _ = tx.send(result);
            });

            let result = rx.await;

            match result {
                Ok(Ok(files)) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            for f in &files {
                                view.expanded_files.insert(f.file_path.clone());
                            }
                            view.files = files;
                            view.status = DiffStatus::Loaded;
                            view.rebuild_flat_rows();
                            cx.notify();
                        });
                    })
                    .ok();
                }
                Ok(Err(e)) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.status = DiffStatus::Error(e);
                            cx.notify();
                        });
                    })
                    .ok();
                }
                Err(_) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.status = DiffStatus::Error("Discovery cancelled".into());
                            cx.notify();
                        });
                    })
                    .ok();
                }
            }
        })
        .detach();
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        self.status = DiffStatus::Loading;
        self.files.clear();
        self.flat_rows.clear();
        cx.notify();
        Self::spawn_discovery(self.source.clone(), self.show_uncommitted, cx);
    }

    fn toggle_uncommitted(&mut self, cx: &mut Context<Self>) {
        self.show_uncommitted = !self.show_uncommitted;
        self.refresh(cx);
    }

    // ── Flat row management ──────────────────────────────────────────────

    fn rebuild_flat_rows(&mut self) {
        self.flat_rows.clear();
        for (fi, file) in self.files.iter().enumerate() {
            if !self.passes_filter(file) {
                continue;
            }
            self.flat_rows.push(FlatRow::FileHeader { file_idx: fi });
            if self.expanded_files.contains(&file.file_path) {
                for (hi, hunk) in file.hunks.iter().enumerate() {
                    for li in 0..hunk.lines.len() {
                        self.flat_rows.push(FlatRow::DiffLine {
                            file_idx: fi,
                            hunk_idx: hi,
                            line_idx: li,
                        });
                    }
                }
            }
        }
    }

    fn passes_filter(&self, file: &FileDiff) -> bool {
        if let Some(filter) = &self.selected_file_filter {
            if &file.file_path != filter {
                return false;
            }
        }
        if !self.search_term.is_empty() {
            let term = self.search_term.to_lowercase();
            let path_match = file.file_path.to_lowercase().contains(&term);
            let content_match = file.hunks.iter().any(|h| {
                h.lines
                    .iter()
                    .any(|l| l.content.to_lowercase().contains(&term))
            });
            return path_match || content_match;
        }
        true
    }

    fn toggle_file_expand(&mut self, path: &str) {
        if self.expanded_files.contains(path) {
            self.expanded_files.remove(path);
        } else {
            self.expanded_files.insert(path.to_string());
        }
    }

    /// Called when a file is clicked in the left tree panel.
    /// Sets filter, expands the file, and scrolls the hunk list to it.
    fn select_file_from_tree(&mut self, path: &str, cx: &mut Context<Self>) {
        if self.selected_file_filter.as_deref() == Some(path) {
            self.selected_file_filter = None;
            self.expanded_files.remove(path);
        } else {
            self.selected_file_filter = Some(path.to_string());
            self.expanded_files.insert(path.to_string());
        }
        self.rebuild_flat_rows();
        // Scroll to the file's header row
        let target_path = path.to_string();
        if let Some(pos) = self.flat_rows.iter().position(|r| match r {
            FlatRow::FileHeader { file_idx } => self
                .files
                .get(*file_idx)
                .map(|f| f.file_path == target_path)
                .unwrap_or(false),
            _ => false,
        }) {
            self.scroll_handle.scroll_to_item(pos, ScrollStrategy::Top);
        }
        cx.notify();
    }

    // ── Action handlers ────────────────────────────────────────────────

    /// Get indices of files that pass the current filter
    fn filtered_file_indices(&self) -> Vec<usize> {
        self.files
            .iter()
            .enumerate()
            .filter(|(_, f)| self.passes_filter(f))
            .map(|(i, _)| i)
            .collect()
    }

    fn next_file(&mut self, _: &NextDiffFile, _: &mut Window, cx: &mut Context<Self>) {
        let indices = self.filtered_file_indices();
        if indices.is_empty() {
            return;
        }
        let next = match self.selected_file_idx {
            Some(idx) => {
                let pos = indices.iter().position(|&i| i == idx).unwrap_or(0);
                if pos + 1 < indices.len() {
                    indices[pos + 1]
                } else {
                    indices[pos]
                }
            }
            None => indices[0],
        };
        self.selected_file_idx = Some(next);
        self.scroll_to_file_header(next);
        cx.notify();
    }

    fn prev_file(&mut self, _: &PrevDiffFile, _: &mut Window, cx: &mut Context<Self>) {
        let indices = self.filtered_file_indices();
        if indices.is_empty() {
            return;
        }
        let prev = match self.selected_file_idx {
            Some(idx) => {
                let pos = indices.iter().position(|&i| i == idx).unwrap_or(0);
                if pos > 0 {
                    indices[pos - 1]
                } else {
                    indices[0]
                }
            }
            None => indices[0],
        };
        self.selected_file_idx = Some(prev);
        self.scroll_to_file_header(prev);
        cx.notify();
    }

    fn toggle_file_action(&mut self, _: &ToggleDiffFile, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(file_idx) = self.selected_file_idx {
            if let Some(file) = self.files.get(file_idx) {
                let path = file.file_path.clone();
                self.toggle_file_expand(&path);
                self.rebuild_flat_rows();
                cx.notify();
            }
        }
    }

    fn refresh_action(&mut self, _: &RefreshDiff, _: &mut Window, cx: &mut Context<Self>) {
        self.refresh(cx);
    }

    fn focus_search(&mut self, _: &FocusDiffSearch, window: &mut Window, cx: &mut Context<Self>) {
        let handle = self.search_input.read(cx).focus_handle(cx);
        window.focus(&handle);
    }

    fn scroll_to_file_header(&self, file_idx: usize) {
        if let Some(pos) = self
            .flat_rows
            .iter()
            .position(|r| matches!(r, FlatRow::FileHeader { file_idx: fi } if *fi == file_idx))
        {
            self.scroll_handle
                .scroll_to_item(pos, ScrollStrategy::Center);
        }
    }

    // ── Render: flat row dispatcher ──────────────────────────────────────

    fn render_flat_row(
        &self,
        idx: usize,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let row = self.flat_rows[idx];
        match row {
            FlatRow::FileHeader { file_idx } => self.render_file_header_row(file_idx, theme, cx),
            FlatRow::DiffLine {
                file_idx,
                hunk_idx,
                line_idx,
            } => {
                let line = &self.files[file_idx].hunks[hunk_idx].lines[line_idx];
                self.render_diff_line_row(line, theme)
            }
        }
    }

    fn render_file_header_row(
        &self,
        file_idx: usize,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let file = &self.files[file_idx];
        let path = file.file_path.clone();
        let path_toggle = path.clone();
        let is_expanded = self.expanded_files.contains(&path);
        let is_selected = self.selected_file_idx == Some(file_idx);

        let badge_color = match file.change_type {
            FileChangeType::Added => theme.diff_badge_added,
            FileChangeType::Deleted => theme.diff_badge_deleted,
            FileChangeType::Modified => theme.diff_badge_modified,
            FileChangeType::Renamed => theme.diff_badge_renamed,
        };
        let additions = file.additions;
        let deletions = file.deletions;

        div()
            .id(ElementId::Name(SharedString::from(format!(
                "fhdr-{}",
                file_idx
            ))))
            .h(px(ROW_HEIGHT))
            .w_full()
            .flex()
            .items_center()
            .gap_1()
            .px_3()
            .cursor_pointer()
            .bg(if is_selected {
                theme.hover
            } else {
                theme.surface
            })
            .border_b_1()
            .border_color(theme.diff_hunk_border)
            .when(is_selected, |el| {
                el.border_l_2().border_color(theme.diff_selected_border)
            })
            .hover(|s| s.bg(theme.hover))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.toggle_file_expand(&path_toggle);
                this.rebuild_flat_rows();
                cx.notify();
            }))
            // Chevron
            .child(
                svg()
                    .path(if is_expanded {
                        "icons/chevron-down.svg"
                    } else {
                        "icons/chevron-right.svg"
                    })
                    .size(px(12.0))
                    .text_color(theme.muted),
            )
            // Badge
            .child(
                svg()
                    .path(match file.change_type {
                        FileChangeType::Added => "icons/diff-added.svg",
                        FileChangeType::Deleted => "icons/diff-removed.svg",
                        FileChangeType::Modified => "icons/diff-modified.svg",
                        FileChangeType::Renamed => "icons/diff-renamed.svg",
                    })
                    .size(px(14.0))
                    .text_color(badge_color),
            )
            // File path
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.0))
                    .text_color(theme.foreground)
                    .font_family("Menlo")
                    .overflow_hidden()
                    .child(path),
            )
            // Stats
            .when(additions > 0, |el| {
                el.child(
                    div()
                        .text_size(px(11.0))
                        .text_color(theme.git_additions)
                        .child(format!("+{}", additions)),
                )
            })
            .when(deletions > 0, |el| {
                el.child(
                    div()
                        .text_size(px(11.0))
                        .text_color(theme.git_deletions)
                        .child(format!("-{}", deletions)),
                )
            })
            .into_any_element()
    }

    fn render_diff_line_row(&self, line: &DiffLine, theme: &Theme) -> gpui::AnyElement {
        let (bg, gutter_bg, indicator) = match line.line_type {
            DiffLineType::Add => (theme.diff_add_bg, theme.diff_gutter_add, "+"),
            DiffLineType::Remove => (theme.diff_remove_bg, theme.diff_gutter_remove, "-"),
            DiffLineType::Context => (
                gpui::hsla(0.0, 0.0, 0.0, 0.0),
                gpui::hsla(0.0, 0.0, 0.0, 0.0),
                " ",
            ),
            DiffLineType::Header => (theme.diff_header_bg, theme.diff_header_bg, "@"),
        };

        let old_num = line
            .old_line_number
            .map(|n| format!("{}", n))
            .unwrap_or_default();
        let new_num = line
            .new_line_number
            .map(|n| format!("{}", n))
            .unwrap_or_default();

        div()
            .h(px(ROW_HEIGHT))
            .w_full()
            .flex()
            .items_center()
            .bg(bg)
            .font_family("Menlo")
            .text_size(px(12.0))
            // Old line number
            .child(
                div()
                    .w(px(48.0))
                    .px_1()
                    .flex_shrink_0()
                    .text_color(theme.diff_line_number)
                    .bg(gutter_bg)
                    .text_size(px(11.0))
                    .child(div().w_full().text_right().child(old_num)),
            )
            // New line number
            .child(
                div()
                    .w(px(48.0))
                    .px_1()
                    .flex_shrink_0()
                    .text_color(theme.diff_line_number)
                    .bg(gutter_bg)
                    .text_size(px(11.0))
                    .child(div().w_full().text_right().child(new_num)),
            )
            // Indicator (+/-/space)
            .child(
                div()
                    .w(px(16.0))
                    .flex_shrink_0()
                    .text_color(match line.line_type {
                        DiffLineType::Add => theme.git_additions,
                        DiffLineType::Remove => theme.git_deletions,
                        _ => theme.muted,
                    })
                    .child(indicator),
            )
            // Content
            .child(
                div()
                    .flex_1()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_color(theme.foreground)
                    .child(if line.content.is_empty() {
                        " ".to_string()
                    } else {
                        line.content.clone()
                    }),
            )
            .into_any_element()
    }

    // ── Render: panels ───────────────────────────────────────────────────

    fn render_controls(&self, theme: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        let total_additions: u32 = self.files.iter().map(|f| f.additions).sum();
        let total_deletions: u32 = self.files.iter().map(|f| f.deletions).sum();
        let file_count = self.files.len();

        div()
            .h(px(36.0))
            .flex()
            .items_center()
            .px_3()
            .gap_2()
            .border_b_1()
            .border_color(theme.border)
            .bg(theme.diff_controls_bg)
            .text_size(px(11.0))
            // Refresh
            .child(
                icon_button("icons/refresh.svg", 14.0, theme.muted, theme)
                    .id("diff-refresh")
                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
            )
            .child(div().h(px(12.0)).w(px(1.0)).bg(theme.border))
            // Uncommitted toggle
            .child(
                div()
                    .id("diff-uncommitted")
                    .flex()
                    .items_center()
                    .gap_1()
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_uncommitted(cx)))
                    .child(div().text_color(theme.muted).child("Uncommitted"))
                    .child(
                        div()
                            .w(px(12.0))
                            .h(px(12.0))
                            .rounded(px(2.0))
                            .border_1()
                            .border_color(if self.show_uncommitted {
                                theme.accent
                            } else {
                                theme.muted
                            })
                            .bg(if self.show_uncommitted {
                                theme.accent
                            } else {
                                gpui::hsla(0.0, 0.0, 0.0, 0.0)
                            })
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_color(if self.show_uncommitted {
                                theme.background
                            } else {
                                gpui::hsla(0.0, 0.0, 0.0, 0.0)
                            })
                            .child(svg().path("icons/check.svg").size(px(10.0))),
                    ),
            )
            .child(div().flex_1())
            // Stats
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_color(theme.muted)
                    .child(format!(
                        "{} file{}",
                        file_count,
                        if file_count == 1 { "" } else { "s" }
                    ))
                    .when(total_additions > 0, |el| {
                        el.child(
                            div()
                                .text_color(theme.git_additions)
                                .child(format!("+{}", total_additions)),
                        )
                    })
                    .when(total_deletions > 0, |el| {
                        el.child(
                            div()
                                .text_color(theme.git_deletions)
                                .child(format!("-{}", total_deletions)),
                        )
                    }),
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
                        .id("diff-search-clear")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.search_input.update(cx, |input, cx| input.clear(cx));
                        })),
                )
            })
            .into_any_element()
    }

    fn render_file_tree(&self, theme: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        let mut tree = div()
            .id("file-tree")
            .w(px(240.0))
            .h_full()
            .flex()
            .flex_col()
            .border_r_1()
            .border_color(theme.border)
            .overflow_y_scroll()
            // Header
            .child(
                div()
                    .px_3()
                    .py_2()
                    .flex()
                    .items_center()
                    .gap_2()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .text_size(px(11.0))
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(theme.muted)
                            .child("Files"),
                    )
                    .when(self.selected_file_filter.is_some(), |el| {
                        el.child(
                            div()
                                .id("clear-file-filter")
                                .flex()
                                .items_center()
                                .gap_1()
                                .px(px(4.0))
                                .py(px(1.0))
                                .rounded(px(3.0))
                                .bg(theme.surface)
                                .text_size(px(10.0))
                                .text_color(theme.accent)
                                .cursor_pointer()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.selected_file_filter = None;
                                    this.rebuild_flat_rows();
                                    cx.notify();
                                }))
                                .child(
                                    svg()
                                        .path("icons/close.svg")
                                        .size(px(10.0))
                                        .text_color(theme.accent),
                                )
                                .child("clear filter"),
                        )
                    }),
            );

        for file in &self.files {
            let path = file.file_path.clone();
            let path_click = path.clone();
            let is_filtered = self.selected_file_filter.as_ref() == Some(&path);

            let badge_color = match file.change_type {
                FileChangeType::Added => theme.diff_badge_added,
                FileChangeType::Deleted => theme.diff_badge_deleted,
                FileChangeType::Modified => theme.diff_badge_modified,
                FileChangeType::Renamed => theme.diff_badge_renamed,
            };
            let badge_icon = match file.change_type {
                FileChangeType::Added => "icons/diff-added.svg",
                FileChangeType::Deleted => "icons/diff-removed.svg",
                FileChangeType::Modified => "icons/diff-modified.svg",
                FileChangeType::Renamed => "icons/diff-renamed.svg",
            };

            let display_name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path)
                .to_string();
            let dir = std::path::Path::new(&path)
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or("")
                .to_string();

            tree = tree.child(
                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "ftree-{}",
                        path
                    ))))
                    .px_2()
                    .py(px(3.0))
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .cursor_pointer()
                    .bg(if is_filtered {
                        theme.surface
                    } else {
                        gpui::hsla(0.0, 0.0, 0.0, 0.0)
                    })
                    .hover(|s| s.bg(theme.hover))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.select_file_from_tree(&path_click, cx);
                    }))
                    // Badge
                    .child(
                        svg()
                            .path(badge_icon)
                            .size(px(14.0))
                            .text_color(badge_color),
                    )
                    // File name + dir
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .text_color(theme.foreground)
                                    .child(display_name),
                            )
                            .when(!dir.is_empty(), |el| {
                                el.child(
                                    div().text_size(px(10.0)).text_color(theme.muted).child(dir),
                                )
                            }),
                    )
                    // Stats
                    .when(file.additions > 0, |el| {
                        el.child(
                            div()
                                .text_size(px(10.0))
                                .text_color(theme.git_additions)
                                .child(format!("+{}", file.additions)),
                        )
                    })
                    .when(file.deletions > 0, |el| {
                        el.child(
                            div()
                                .text_size(px(10.0))
                                .text_color(theme.git_deletions)
                                .child(format!("-{}", file.deletions)),
                        )
                    }),
            );
        }

        tree.into_any_element()
    }

    fn render_hunk_list(&self, theme: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        if self.flat_rows.is_empty() {
            return div()
                .flex_1()
                .flex()
                .items_center()
                .justify_center()
                .text_color(theme.muted)
                .text_size(px(13.0))
                .child(if !self.search_term.is_empty() {
                    "No files match search"
                } else {
                    "No changes found"
                })
                .into_any_element();
        }

        let theme = theme.clone();
        uniform_list(
            "hunk-list",
            self.flat_rows.len(),
            cx.processor(move |this, range: Range<usize>, _win, cx| {
                let mut items = Vec::with_capacity(range.end - range.start);
                for i in range {
                    items.push(this.render_flat_row(i, &theme, cx));
                }
                items
            }),
        )
        .flex_1()
        .track_scroll(&self.scroll_handle)
        .into_any_element()
    }
}

// ── Trait impls ──────────────────────────────────────────────────────────

impl Focusable for DiffView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for DiffView {
    #[allow(refining_impl_trait)]
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> gpui::AnyElement {
        let theme = Theme::dark();

        match &self.status {
            DiffStatus::Loading => div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(theme.muted)
                .text_size(px(13.0))
                .child(format!(
                    "Loading diff for {}...",
                    self.source.display_name()
                ))
                .into_any_element(),

            DiffStatus::Error(msg) => {
                let msg = msg.clone();
                div()
                    .size_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap_2()
                    .child(
                        div()
                            .text_color(theme.git_deletions)
                            .text_size(px(13.0))
                            .child("Failed to load diff"),
                    )
                    .child(div().text_color(theme.muted).text_size(px(11.0)).child(msg))
                    .child(
                        div()
                            .id("diff-retry")
                            .mt_2()
                            .px_3()
                            .py_1()
                            .rounded(px(4.0))
                            .border_1()
                            .border_color(theme.border)
                            .text_size(px(11.0))
                            .text_color(theme.accent)
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.surface))
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx)))
                            .child("Retry"),
                    )
                    .into_any_element()
            }

            DiffStatus::Loaded => {
                let mut container = div()
                    .size_full()
                    .flex()
                    .flex_col()
                    .bg(theme.surface)
                    .key_context("DiffView")
                    .track_focus(&self.focus_handle(cx))
                    .on_action(cx.listener(Self::next_file))
                    .on_action(cx.listener(Self::prev_file))
                    .on_action(cx.listener(Self::toggle_file_action))
                    .on_action(cx.listener(Self::refresh_action))
                    .on_action(cx.listener(Self::focus_search));

                container = container.child(self.render_controls(&theme, cx));
                container = container.child(self.render_search_bar(&theme, cx));

                container = container.child(
                    div()
                        .flex_1()
                        .flex()
                        .overflow_hidden()
                        .child(self.render_file_tree(&theme, cx))
                        .child(self.render_hunk_list(&theme, cx)),
                );

                container.into_any_element()
            }
        }
    }
}
