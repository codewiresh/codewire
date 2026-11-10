//! Quick Open modal (Cmd+P) for fuzzy file finding.
//!
//! Provides a centered modal overlay with text input and fuzzy-matched
//! file list from the active workspace.

use crate::file_browser::FileSource;
use crate::theme::Theme;
use gpui::{
    App, Context, ElementId, Entity, EventEmitter, FocusHandle, Focusable, SharedString, Window,
    actions, div, prelude::*, px,
};

actions!(quick_open, [Dismiss]);

/// Event emitted when a file is selected from Quick Open
#[derive(Clone, Debug)]
pub struct QuickOpenFileSelected {
    pub source: FileSource,
}

impl EventEmitter<QuickOpenFileSelected> for QuickOpen {}

/// A file entry in the quick open list
#[derive(Clone, Debug)]
struct FileEntry {
    /// Relative path from workspace root
    path: String,
    /// The FileSource to open this file
    source: FileSource,
    /// Fuzzy match score (higher is better)
    score: i32,
}

pub struct QuickOpen {
    visible: bool,
    query: String,
    /// All known file paths for the active workspace
    file_index: Vec<FileEntry>,
    /// Filtered results based on query
    filtered: Vec<FileEntry>,
    /// Currently highlighted result index
    selected_index: usize,
    focus_handle: FocusHandle,
}

impl QuickOpen {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            visible: false,
            query: String::new(),
            file_index: Vec::new(),
            filtered: Vec::new(),
            selected_index: 0,
            focus_handle: cx.focus_handle(),
        }
    }

    pub fn show(&mut self, cx: &mut Context<Self>) {
        self.visible = true;
        self.query.clear();
        self.selected_index = 0;
        self.filtered = self.file_index.clone();
        // Truncate to reasonable display count
        self.filtered.truncate(100);
        cx.notify();
    }

    pub fn hide(&mut self, cx: &mut Context<Self>) {
        self.visible = false;
        self.query.clear();
        self.selected_index = 0;
        cx.notify();
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Update the file index from a list of file paths
    pub fn update_file_index(
        &mut self,
        entries: Vec<(String, FileSource)>,
        cx: &mut Context<Self>,
    ) {
        self.file_index = entries
            .into_iter()
            .map(|(path, source)| FileEntry {
                path,
                source,
                score: 0,
            })
            .collect();
        if self.visible {
            self.apply_filter();
        }
        cx.notify();
    }

    /// Build file index from a local directory (background walk)
    pub fn index_local_directory(entity: Entity<Self>, root_path: String, cx: &mut Context<Self>) {
        cx.spawn(async move |_, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();
            let walk_path = root_path.clone();
            std::thread::spawn(move || {
                let mut entries = Vec::new();
                Self::walk_dir(&walk_path, &walk_path, &mut entries);
                let _ = tx.send(entries);
            });

            if let Ok(entries) = rx.await {
                let file_entries: Vec<(String, FileSource)> = entries
                    .into_iter()
                    .map(|rel_path| {
                        let source = FileSource::Local {
                            root_path: format!("{}/{}", root_path, rel_path),
                        };
                        (rel_path, source)
                    })
                    .collect();

                cx.update(|cx| {
                    entity.update(cx, |this, cx| {
                        this.update_file_index(file_entries, cx);
                    });
                });
            }
        })
        .detach();
    }

    fn walk_dir(base: &str, current: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden files and common non-source directories
            if file_name.starts_with('.')
                || file_name == "node_modules"
                || file_name == "target"
                || file_name == "__pycache__"
            {
                continue;
            }

            if path.is_dir() {
                Self::walk_dir(base, &path.to_string_lossy(), out);
            } else {
                // Store relative path
                if let Some(rel) = path.to_string_lossy().strip_prefix(base) {
                    let rel = rel.trim_start_matches('/');
                    out.push(rel.to_string());
                }
            }
        }
    }

    fn apply_filter(&mut self) {
        let query = self.query.to_lowercase();
        if query.is_empty() {
            self.filtered = self.file_index.clone();
            self.filtered.truncate(100);
        } else {
            self.filtered = self
                .file_index
                .iter()
                .filter_map(|entry| {
                    let score = fuzzy_score(&entry.path, &query);
                    if score > 0 {
                        Some(FileEntry {
                            score,
                            ..entry.clone()
                        })
                    } else {
                        None
                    }
                })
                .collect();
            self.filtered.sort_by(|a, b| b.score.cmp(&a.score));
            self.filtered.truncate(100);
        }
        self.selected_index = 0;
    }

    fn on_input(&mut self, new_text: &str, cx: &mut Context<Self>) {
        self.query = new_text.to_string();
        self.apply_filter();
        cx.notify();
    }

    fn select_next(&mut self, cx: &mut Context<Self>) {
        if !self.filtered.is_empty() {
            self.selected_index = (self.selected_index + 1).min(self.filtered.len() - 1);
            cx.notify();
        }
    }

    fn select_prev(&mut self, cx: &mut Context<Self>) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            cx.notify();
        }
    }

    fn confirm_selection(&mut self, cx: &mut Context<Self>) {
        if let Some(entry) = self.filtered.get(self.selected_index) {
            cx.emit(QuickOpenFileSelected {
                source: entry.source.clone(),
            });
        }
        self.hide(cx);
    }

    fn dismiss(&mut self, _: &Dismiss, _window: &mut Window, cx: &mut Context<Self>) {
        self.hide(cx);
    }
}

/// Simple fuzzy matching: returns a score > 0 if all query characters appear in order in the path
fn fuzzy_score(path: &str, query: &str) -> i32 {
    let path_lower = path.to_lowercase();
    let path_chars: Vec<char> = path_lower.chars().collect();
    let query_chars: Vec<char> = query.chars().collect();

    if query_chars.is_empty() {
        return 1;
    }

    let mut score: i32 = 0;
    let mut qi = 0;
    let mut last_match = None;

    for (pi, &pc) in path_chars.iter().enumerate() {
        if qi < query_chars.len() && pc == query_chars[qi] {
            // Bonus for consecutive matches
            if let Some(last) = last_match {
                if pi == last + 1 {
                    score += 3;
                }
            }
            // Bonus for matching after separator (/ or _)
            if pi == 0
                || path_chars[pi - 1] == '/'
                || path_chars[pi - 1] == '_'
                || path_chars[pi - 1] == '-'
            {
                score += 5;
            }
            score += 1;
            last_match = Some(pi);
            qi += 1;
        }
    }

    if qi == query_chars.len() {
        // Bonus for shorter paths (prefer closer matches)
        score += (100 - path.len().min(100) as i32).max(0);
        score
    } else {
        0 // Not all query chars matched
    }
}

impl Focusable for QuickOpen {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for QuickOpen {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        if !self.visible {
            return div().into_any_element();
        }

        let query = self.query.clone();
        let selected_idx = self.selected_index;

        // Build result list (max 15 visible)
        let visible_results: Vec<_> = self.filtered.iter().take(15).cloned().collect();

        let dismiss_bg = div()
            .id("quick-open-dismiss")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .bg(gpui::hsla(0.0, 0.0, 0.0, 0.3))
            .on_click(cx.listener(|this, _, _, cx| {
                this.hide(cx);
            }));

        let input_field = div()
            .w_full()
            .h(px(36.0))
            .px_3()
            .flex()
            .items_center()
            .bg(theme.background)
            .border_b_1()
            .border_color(theme.border)
            .text_size(px(14.0))
            .text_color(theme.foreground)
            .child(if query.is_empty() {
                div()
                    .text_color(theme.muted)
                    .child("Type to search files...")
            } else {
                div().child(query)
            });

        let results = div()
            .id("quick-open-results")
            .w_full()
            .max_h(px(400.0))
            .overflow_y_scroll()
            .children(visible_results.iter().enumerate().map(|(idx, entry)| {
                let is_selected = idx == selected_idx;
                let source = entry.source.clone();

                // Extract filename from path for display
                let file_name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
                let dir_path = if entry.path.contains('/') {
                    entry.path.rsplitn(2, '/').nth(1).unwrap_or("")
                } else {
                    ""
                };

                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "qo-result-{}",
                        idx
                    ))))
                    .w_full()
                    .h(px(28.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .gap_2()
                    .bg(if is_selected {
                        theme.explorer_selected_bg
                    } else {
                        theme.surface
                    })
                    .cursor_pointer()
                    .hover_style(|s| s.bg(theme.hover))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.emit(QuickOpenFileSelected {
                            source: source.clone(),
                        });
                        this.hide(cx);
                    }))
                    .child(
                        div()
                            .text_size(px(13.0))
                            .text_color(theme.foreground)
                            .child(file_name.to_string()),
                    )
                    .when(!dir_path.is_empty(), |d| {
                        d.child(
                            div()
                                .text_size(px(11.0))
                                .text_color(theme.muted)
                                .child(dir_path.to_string()),
                        )
                    })
            }));

        let modal = div()
            .w(px(500.0))
            .mt(px(80.0))
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .rounded(px(8.0))
            .shadow_lg()
            .overflow_hidden()
            .key_context("QuickOpen")
            .track_focus(&self.focus_handle(cx))
            .on_action(cx.listener(Self::dismiss))
            .on_key_down(cx.listener(|this, event: &gpui::KeyDownEvent, _, cx| {
                match event.keystroke.key.as_str() {
                    "escape" => this.hide(cx),
                    "enter" => this.confirm_selection(cx),
                    "up" => this.select_prev(cx),
                    "down" => this.select_next(cx),
                    "backspace" => {
                        let mut q = this.query.clone();
                        q.pop();
                        this.on_input(&q, cx);
                    }
                    key if key.len() == 1 => {
                        let q = format!("{}{}", this.query, key);
                        this.on_input(&q, cx);
                    }
                    _ => {}
                }
            }))
            .child(input_field)
            .child(results);

        div()
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .child(dismiss_bg)
            .child(modal)
            .into_any_element()
    }
}
