//! File editor component with full editing support.
//!
//! Provides a read/write file editor using uniform_list for virtualized
//! line rendering and EntityInputHandler for text editing with IME support.

use crate::file_browser::FileSource;
use crate::theme::Theme;
use gpui::{
    App, Bounds, Context, CursorStyle, Element, ElementId, ElementInputHandler, Entity,
    EntityInputHandler, EventEmitter, FocusHandle, Focusable, GlobalElementId, LayoutId, Pixels,
    ShapedLine, SharedString, Style, TextRun, UTF16Selection, UniformListScrollHandle, Window,
    actions, div, fill, point, prelude::*, px, size, uniform_list,
};
use std::ops::Range;
use unicode_segmentation::*;

// ── Actions ──────────────────────────────────────────────────────────────

actions!(
    editor,
    [
        MoveUp,
        MoveDown,
        MoveLineStart,
        MoveLineEnd,
        EditorBackspace,
        EditorDelete,
        EditorLeft,
        EditorRight,
        EditorSelectAll,
        EditorPaste,
        EditorCopy,
        EditorCut,
        EditorEnter,
        SaveFile,
        UndoEdit,
        RedoEdit
    ]
);

// ── Types ────────────────────────────────────────────────────────────────

enum EditorStatus {
    Loading,
    Loaded,
    Error(String),
    Saving,
}

/// Undo/redo entry
#[derive(Clone)]
struct UndoEntry {
    content: String,
    cursor: Range<usize>,
}

/// Fixed row height for uniform_list
const ROW_HEIGHT: f32 = 22.0;
/// Max undo stack size
const MAX_UNDO: usize = 100;

/// Event emitted when the modified state changes
#[derive(Clone, Debug)]
pub struct FileModified {
    pub source_id: String,
    pub is_modified: bool,
}

// ── EditorView ───────────────────────────────────────────────────────────

pub struct EditorView {
    source: FileSource,
    status: EditorStatus,
    /// Lines of the file (derived from content)
    lines: Vec<String>,
    /// Flat content string (authoritative buffer)
    content: String,
    /// Snapshot at load for dirty tracking
    original_content: String,
    /// Byte offsets into content
    selected_range: Range<usize>,
    selection_reversed: bool,
    marked_range: Option<Range<usize>>,
    is_modified: bool,
    undo_stack: Vec<UndoEntry>,
    redo_stack: Vec<UndoEntry>,
    scroll_handle: UniformListScrollHandle,
    focus_handle: FocusHandle,
    /// Layout cache for the active cursor line (used by EditorLineElement)
    active_line_layout: Option<ShapedLine>,
    active_line_bounds: Option<Bounds<Pixels>>,
}

impl EventEmitter<FileModified> for EditorView {}

impl EditorView {
    /// Returns whether the editor has unsaved changes
    pub fn is_modified(&self) -> bool {
        self.is_modified
    }
}

impl EditorView {
    pub fn new(source: FileSource, cx: &mut Context<Self>) -> Self {
        let view = Self {
            source: source.clone(),
            status: EditorStatus::Loading,
            lines: Vec::new(),
            content: String::new(),
            original_content: String::new(),
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            is_modified: false,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            scroll_handle: UniformListScrollHandle::new(),
            focus_handle: cx.focus_handle(),
            active_line_layout: None,
            active_line_bounds: None,
        };

        Self::spawn_load(source, cx);
        view
    }

    // ── Loading ──────────────────────────────────────────────────────────

    fn spawn_load(source: FileSource, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();

            let FileSource::Local { root_path } = source;
            std::thread::spawn(move || {
                let result = std::fs::read_to_string(&root_path)
                    .map_err(|e| format!("Failed to read file: {}", e));
                let _ = tx.send(result);
            });

            let result = rx.await;

            match result {
                Ok(Ok(content)) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.content = content.clone();
                            view.original_content = content;
                            view.resync_lines();
                            view.status = EditorStatus::Loaded;
                            cx.notify();
                        });
                    })
                    .ok();
                }
                Ok(Err(e)) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.status = EditorStatus::Error(e);
                            cx.notify();
                        });
                    })
                    .ok();
                }
                Err(_) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.status = EditorStatus::Error("Load cancelled".into());
                            cx.notify();
                        });
                    })
                    .ok();
                }
            }
        })
        .detach();
    }

    fn resync_lines(&mut self) {
        self.lines = self.content.split('\n').map(String::from).collect();
    }

    // ── Coordinate helpers ───────────────────────────────────────────────

    /// Convert a byte offset in content to (line, col) where col is byte offset within line
    fn byte_offset_to_line_col(&self, offset: usize) -> (usize, usize) {
        let mut remaining = offset;
        for (i, line) in self.lines.iter().enumerate() {
            if remaining <= line.len() {
                return (i, remaining);
            }
            remaining -= line.len() + 1; // +1 for \n
        }
        // Past end — return last position
        let last = self.lines.len().saturating_sub(1);
        (last, self.lines.get(last).map_or(0, |l| l.len()))
    }

    /// Convert (line, col) to byte offset in content
    fn line_col_to_byte_offset(&self, line: usize, col: usize) -> usize {
        let mut offset = 0;
        for (i, l) in self.lines.iter().enumerate() {
            if i == line {
                return offset + col.min(l.len());
            }
            offset += l.len() + 1; // +1 for \n
        }
        self.content.len()
    }

    fn cursor_offset(&self) -> usize {
        if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        }
    }

    fn move_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        let offset = offset.min(self.content.len());
        self.selected_range = offset..offset;
        cx.notify();
    }

    fn select_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        let offset = offset.min(self.content.len());
        if self.selection_reversed {
            self.selected_range.start = offset;
        } else {
            self.selected_range.end = offset;
        }
        if self.selected_range.end < self.selected_range.start {
            self.selection_reversed = !self.selection_reversed;
            self.selected_range = self.selected_range.end..self.selected_range.start;
        }
        cx.notify();
    }

    fn previous_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .rev()
            .find_map(|(idx, _)| (idx < offset).then_some(idx))
            .unwrap_or(0)
    }

    fn next_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .find_map(|(idx, _)| (idx > offset).then_some(idx))
            .unwrap_or(self.content.len())
    }

    // ── UTF-16 conversion (for platform IME) ─────────────────────────────

    fn offset_from_utf16(&self, offset: usize) -> usize {
        let mut utf8_offset = 0;
        let mut utf16_count = 0;
        for ch in self.content.chars() {
            if utf16_count >= offset {
                break;
            }
            utf16_count += ch.len_utf16();
            utf8_offset += ch.len_utf8();
        }
        utf8_offset
    }

    fn offset_to_utf16(&self, offset: usize) -> usize {
        let mut utf16_offset = 0;
        let mut utf8_count = 0;
        for ch in self.content.chars() {
            if utf8_count >= offset {
                break;
            }
            utf8_count += ch.len_utf8();
            utf16_offset += ch.len_utf16();
        }
        utf16_offset
    }

    fn range_to_utf16(&self, range: &Range<usize>) -> Range<usize> {
        self.offset_to_utf16(range.start)..self.offset_to_utf16(range.end)
    }

    fn range_from_utf16(&self, range_utf16: &Range<usize>) -> Range<usize> {
        self.offset_from_utf16(range_utf16.start)..self.offset_from_utf16(range_utf16.end)
    }

    // ── Undo/Redo ────────────────────────────────────────────────────────

    fn push_undo(&mut self) {
        self.undo_stack.push(UndoEntry {
            content: self.content.clone(),
            cursor: self.selected_range.clone(),
        });
        if self.undo_stack.len() > MAX_UNDO {
            self.undo_stack.remove(0);
        }
        self.redo_stack.clear();
    }

    fn update_modified(&mut self, cx: &mut Context<Self>) {
        let was_modified = self.is_modified;
        self.is_modified = self.content != self.original_content;
        if was_modified != self.is_modified {
            cx.emit(FileModified {
                source_id: self.source.source_id(),
                is_modified: self.is_modified,
            });
        }
    }

    // ── Action handlers ──────────────────────────────────────────────────

    fn editor_backspace(
        &mut self,
        _: &EditorBackspace,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.selected_range.is_empty() {
            self.select_to(self.previous_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn editor_delete(&mut self, _: &EditorDelete, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.next_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn editor_left(&mut self, _: &EditorLeft, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.previous_boundary(self.cursor_offset()), cx);
        } else {
            self.move_to(self.selected_range.start, cx);
        }
    }

    fn editor_right(&mut self, _: &EditorRight, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.next_boundary(self.cursor_offset()), cx);
        } else {
            self.move_to(self.selected_range.end, cx);
        }
    }

    fn move_up(&mut self, _: &MoveUp, _: &mut Window, cx: &mut Context<Self>) {
        let (line, col) = self.byte_offset_to_line_col(self.cursor_offset());
        if line > 0 {
            let new_offset = self.line_col_to_byte_offset(line - 1, col);
            self.move_to(new_offset, cx);
        }
    }

    fn move_down(&mut self, _: &MoveDown, _: &mut Window, cx: &mut Context<Self>) {
        let (line, col) = self.byte_offset_to_line_col(self.cursor_offset());
        if line + 1 < self.lines.len() {
            let new_offset = self.line_col_to_byte_offset(line + 1, col);
            self.move_to(new_offset, cx);
        }
    }

    fn move_line_start(&mut self, _: &MoveLineStart, _: &mut Window, cx: &mut Context<Self>) {
        let (line, _) = self.byte_offset_to_line_col(self.cursor_offset());
        let new_offset = self.line_col_to_byte_offset(line, 0);
        self.move_to(new_offset, cx);
    }

    fn move_line_end(&mut self, _: &MoveLineEnd, _: &mut Window, cx: &mut Context<Self>) {
        let (line, _) = self.byte_offset_to_line_col(self.cursor_offset());
        let line_len = self.lines.get(line).map_or(0, |l| l.len());
        let new_offset = self.line_col_to_byte_offset(line, line_len);
        self.move_to(new_offset, cx);
    }

    fn editor_select_all(&mut self, _: &EditorSelectAll, _: &mut Window, cx: &mut Context<Self>) {
        self.selected_range = 0..self.content.len();
        self.selection_reversed = false;
        cx.notify();
    }

    fn editor_copy(&mut self, _: &EditorCopy, _: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() {
            cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
        }
    }

    fn editor_cut(&mut self, _: &EditorCut, window: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() {
            cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
            self.replace_text_in_range(None, "", window, cx);
        }
    }

    fn editor_paste(&mut self, _: &EditorPaste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            self.replace_text_in_range(None, &text, window, cx);
        }
    }

    fn editor_enter(&mut self, _: &EditorEnter, window: &mut Window, cx: &mut Context<Self>) {
        self.replace_text_in_range(None, "\n", window, cx);
    }

    fn undo_edit(&mut self, _: &UndoEdit, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(entry) = self.undo_stack.pop() {
            self.redo_stack.push(UndoEntry {
                content: self.content.clone(),
                cursor: self.selected_range.clone(),
            });
            self.content = entry.content;
            self.selected_range = entry.cursor;
            self.resync_lines();
            self.update_modified(cx);
            cx.notify();
        }
    }

    fn redo_edit(&mut self, _: &RedoEdit, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(entry) = self.redo_stack.pop() {
            self.undo_stack.push(UndoEntry {
                content: self.content.clone(),
                cursor: self.selected_range.clone(),
            });
            self.content = entry.content;
            self.selected_range = entry.cursor;
            self.resync_lines();
            self.update_modified(cx);
            cx.notify();
        }
    }

    pub fn save_file(&mut self, _: &SaveFile, _: &mut Window, cx: &mut Context<Self>) {
        if !self.is_modified {
            return;
        }
        self.status = EditorStatus::Saving;
        cx.notify();

        let source = self.source.clone();
        let content = self.content.clone();

        cx.spawn(async move |this, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();

            let FileSource::Local { root_path } = source;
            std::thread::spawn(move || {
                let result = std::fs::write(&root_path, &content)
                    .map_err(|e| format!("Failed to save: {}", e));
                let _ = tx.send(result);
            });

            let result = rx.await;

            match result {
                Ok(Ok(())) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.original_content = view.content.clone();
                            view.is_modified = false;
                            view.status = EditorStatus::Loaded;
                            cx.emit(FileModified {
                                source_id: view.source.source_id(),
                                is_modified: false,
                            });
                            cx.notify();
                        });
                    })
                    .ok();
                }
                Ok(Err(e)) => {
                    tracing::error!("Save failed: {}", e);
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.status = EditorStatus::Loaded;
                            cx.notify();
                        });
                    })
                    .ok();
                }
                Err(_) => {
                    cx.update(|cx| {
                        let _ = this.update(cx, |view, cx| {
                            view.status = EditorStatus::Loaded;
                            cx.notify();
                        });
                    })
                    .ok();
                }
            }
        })
        .detach();
    }

    // ── Render ───────────────────────────────────────────────────────────

    fn render_line(
        &self,
        line_idx: usize,
        cursor_line: usize,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let line_text = self.lines.get(line_idx).cloned().unwrap_or_default();
        let line_num = line_idx + 1;
        let is_cursor_line = line_idx == cursor_line;

        let line_bg = if is_cursor_line {
            theme.editor_cursor_line
        } else {
            gpui::hsla(0.0, 0.0, 0.0, 0.0)
        };

        if is_cursor_line {
            // Cursor line: use EditorLineElement for input handling
            div()
                .h(px(ROW_HEIGHT))
                .w_full()
                .flex()
                .items_center()
                .bg(line_bg)
                .font_family("Menlo")
                .text_size(px(12.0))
                // Line number gutter
                .child(
                    div()
                        .w(px(48.0))
                        .px_1()
                        .flex_shrink_0()
                        .text_color(theme.foreground)
                        .bg(theme.editor_gutter)
                        .text_size(px(11.0))
                        .child(div().w_full().text_right().child(format!("{}", line_num))),
                )
                // Content with cursor element
                .child(
                    div()
                        .flex_1()
                        .pl_2()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .child(EditorLineElement {
                            editor: cx.entity().clone(),
                        }),
                )
                .into_any_element()
        } else {
            // Check if this line is part of a multi-line selection
            let line_start = self.line_col_to_byte_offset(line_idx, 0);
            let line_end = line_start + line_text.len();
            let sel = &self.selected_range;
            let has_selection = !sel.is_empty() && sel.start < line_end + 1 && sel.end > line_start;

            let mut row = div()
                .h(px(ROW_HEIGHT))
                .w_full()
                .flex()
                .items_center()
                .bg(line_bg)
                .font_family("Menlo")
                .text_size(px(12.0))
                // Line number gutter
                .child(
                    div()
                        .w(px(48.0))
                        .px_1()
                        .flex_shrink_0()
                        .text_color(theme.editor_line_number)
                        .bg(theme.editor_gutter)
                        .text_size(px(11.0))
                        .child(div().w_full().text_right().child(format!("{}", line_num))),
                );

            if has_selection {
                // Show line with selection highlight (simplified: full line bg)
                row = row.child(
                    div()
                        .flex_1()
                        .pl_2()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .bg(gpui::rgba(0x89b4fa20))
                        .text_color(theme.foreground)
                        .child(if line_text.is_empty() {
                            " ".to_string()
                        } else {
                            line_text
                        }),
                );
            } else {
                row = row.child(
                    div()
                        .flex_1()
                        .pl_2()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_color(theme.foreground)
                        .child(if line_text.is_empty() {
                            " ".to_string()
                        } else {
                            line_text
                        }),
                );
            }

            row.into_any_element()
        }
    }
}

// ── EntityInputHandler ───────────────────────────────────────────────────

impl EntityInputHandler for EditorView {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let range = self.range_from_utf16(&range_utf16);
        actual_range.replace(self.range_to_utf16(&range));
        Some(self.content[range].to_string())
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.range_to_utf16(&self.selected_range),
            reversed: self.selection_reversed,
        })
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.marked_range
            .as_ref()
            .map(|range| self.range_to_utf16(range))
    }

    fn unmark_text(&mut self, _window: &mut Window, _cx: &mut Context<Self>) {
        self.marked_range = None;
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.push_undo();

        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());

        self.content =
            self.content[0..range.start].to_owned() + new_text + &self.content[range.end..];
        self.selected_range = range.start + new_text.len()..range.start + new_text.len();
        self.marked_range.take();
        self.resync_lines();
        self.update_modified(cx);
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.push_undo();

        let range = range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());

        self.content =
            self.content[0..range.start].to_owned() + new_text + &self.content[range.end..];

        if !new_text.is_empty() {
            self.marked_range = Some(range.start..range.start + new_text.len());
        } else {
            self.marked_range = None;
        }

        self.selected_range = new_selected_range_utf16
            .as_ref()
            .map(|r| self.range_from_utf16(r))
            .map(|new_range| new_range.start + range.start..new_range.end + range.end)
            .unwrap_or_else(|| range.start + new_text.len()..range.start + new_text.len());

        self.resync_lines();
        self.update_modified(cx);
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let last_layout = self.active_line_layout.as_ref()?;
        let range = self.range_from_utf16(&range_utf16);
        let (cursor_line, _) = self.byte_offset_to_line_col(self.cursor_offset());
        let line_start = self.line_col_to_byte_offset(cursor_line, 0);
        let local_start = range.start.saturating_sub(line_start);
        let local_end = range.end.saturating_sub(line_start);

        Some(Bounds::from_corners(
            point(
                bounds.left() + last_layout.x_for_index(local_start),
                bounds.top(),
            ),
            point(
                bounds.left() + last_layout.x_for_index(local_end),
                bounds.bottom(),
            ),
        ))
    }

    fn character_index_for_point(
        &mut self,
        point: gpui::Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        let line_bounds = self.active_line_bounds?;
        let last_layout = self.active_line_layout.as_ref()?;
        let local = line_bounds.localize(&point)?;
        let utf8_index = last_layout.index_for_x(point.x - local.x)?;

        let (cursor_line, _) = self.byte_offset_to_line_col(self.cursor_offset());
        let line_start = self.line_col_to_byte_offset(cursor_line, 0);
        Some(self.offset_to_utf16(line_start + utf8_index))
    }
}

// ── Trait impls ──────────────────────────────────────────────────────────

impl Focusable for EditorView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for EditorView {
    #[allow(refining_impl_trait)]
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> gpui::AnyElement {
        let theme = Theme::dark();

        match &self.status {
            EditorStatus::Loading => div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(theme.muted)
                .text_size(px(13.0))
                .child(format!("Loading {}...", self.source.display_name()))
                .into_any_element(),

            EditorStatus::Error(msg) => {
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
                            .child("Failed to load file"),
                    )
                    .child(div().text_color(theme.muted).text_size(px(11.0)).child(msg))
                    .into_any_element()
            }

            EditorStatus::Loaded | EditorStatus::Saving => {
                let theme_for_list = theme;
                let line_count = self.lines.len();
                let (cursor_line, _) = self.byte_offset_to_line_col(self.cursor_offset());
                let is_saving = matches!(self.status, EditorStatus::Saving);

                let modified_indicator = if self.is_modified { " *" } else { "" };
                let save_indicator = if is_saving { " (saving...)" } else { "" };

                div()
                    .size_full()
                    .flex()
                    .flex_col()
                    .bg(theme.surface)
                    .key_context("EditorView")
                    .track_focus(&self.focus_handle(cx))
                    .cursor(CursorStyle::IBeam)
                    .on_action(cx.listener(Self::editor_backspace))
                    .on_action(cx.listener(Self::editor_delete))
                    .on_action(cx.listener(Self::editor_left))
                    .on_action(cx.listener(Self::editor_right))
                    .on_action(cx.listener(Self::move_up))
                    .on_action(cx.listener(Self::move_down))
                    .on_action(cx.listener(Self::move_line_start))
                    .on_action(cx.listener(Self::move_line_end))
                    .on_action(cx.listener(Self::editor_select_all))
                    .on_action(cx.listener(Self::editor_copy))
                    .on_action(cx.listener(Self::editor_cut))
                    .on_action(cx.listener(Self::editor_paste))
                    .on_action(cx.listener(Self::editor_enter))
                    .on_action(cx.listener(Self::save_file))
                    .on_action(cx.listener(Self::undo_edit))
                    .on_action(cx.listener(Self::redo_edit))
                    .child(
                        // Status bar
                        div()
                            .h(px(28.0))
                            .flex()
                            .items_center()
                            .px_3()
                            .border_b_1()
                            .border_color(theme.border)
                            .bg(theme.diff_controls_bg)
                            .text_size(px(11.0))
                            .child(
                                div()
                                    .flex_1()
                                    .text_color(theme.foreground)
                                    .overflow_hidden()
                                    .child(format!(
                                        "{}{}{}",
                                        self.source.display_name(),
                                        modified_indicator,
                                        save_indicator,
                                    )),
                            )
                            .child(div().text_color(theme.muted).child(format!(
                                "Ln {}, Col {} | {} lines",
                                cursor_line + 1,
                                {
                                    let (_, col) =
                                        self.byte_offset_to_line_col(self.cursor_offset());
                                    col + 1
                                },
                                line_count,
                            ))),
                    )
                    .child(
                        uniform_list(
                            "editor-lines",
                            line_count,
                            cx.processor(move |this, range: Range<usize>, _win, cx| {
                                let mut items = Vec::with_capacity(range.end - range.start);
                                for i in range {
                                    items.push(this.render_line(
                                        i,
                                        cursor_line,
                                        &theme_for_list,
                                        cx,
                                    ));
                                }
                                items
                            }),
                        )
                        .flex_1()
                        .track_scroll(&self.scroll_handle),
                    )
                    .into_any_element()
            }
        }
    }
}

// ── EditorLineElement ────────────────────────────────────────────────────
// Custom Element for the cursor line that connects to platform IME.

struct EditorLineElement {
    editor: Entity<EditorView>,
}

struct EditorLinePrepaint {
    line: Option<ShapedLine>,
    cursor: Option<gpui::PaintQuad>,
    selection: Option<gpui::PaintQuad>,
}

impl IntoElement for EditorLineElement {
    type Element = Self;
    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for EditorLineElement {
    type RequestLayoutState = ();
    type PrepaintState = EditorLinePrepaint;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut style = Style::default();
        style.size.width = gpui::relative(1.).into();
        style.size.height = window.line_height().into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let theme = Theme::dark();
        let editor = self.editor.read(cx);

        let cursor_offset = editor.cursor_offset();
        let (cursor_line, cursor_col) = editor.byte_offset_to_line_col(cursor_offset);
        let line_text = editor.lines.get(cursor_line).cloned().unwrap_or_default();
        let line_start = editor.line_col_to_byte_offset(cursor_line, 0);
        let selected_range = editor.selected_range.clone();

        let style = window.text_style();
        let display_text: SharedString = if line_text.is_empty() {
            " ".into()
        } else {
            line_text.clone().into()
        };

        let run = TextRun {
            len: display_text.len(),
            font: style.font(),
            color: theme.foreground,
            background_color: None,
            underline: None,
            strikethrough: None,
        };

        let font_size = style.font_size.to_pixels(window.rem_size());
        let shaped = window
            .text_system()
            .shape_line(display_text, font_size, &[run], None);

        let cursor_x = shaped.x_for_index(cursor_col);

        // Determine selection within this line
        let line_end = line_start + line_text.len();
        let sel_start_in_line = if selected_range.start > line_start {
            (selected_range.start - line_start).min(line_text.len())
        } else {
            0
        };
        let sel_end_in_line = if selected_range.end > line_start {
            (selected_range.end - line_start).min(line_text.len())
        } else {
            0
        };

        let has_selection_on_line = !selected_range.is_empty()
            && selected_range.start < line_end + 1
            && selected_range.end > line_start
            && sel_start_in_line != sel_end_in_line;

        let (selection, cursor_quad) = if has_selection_on_line {
            (
                Some(fill(
                    Bounds::from_corners(
                        point(
                            bounds.left() + shaped.x_for_index(sel_start_in_line),
                            bounds.top(),
                        ),
                        point(
                            bounds.left() + shaped.x_for_index(sel_end_in_line),
                            bounds.bottom(),
                        ),
                    ),
                    gpui::rgba(0x89b4fa30),
                )),
                None,
            )
        } else {
            (
                None,
                Some(fill(
                    Bounds::new(
                        point(bounds.left() + cursor_x, bounds.top()),
                        size(px(2.), bounds.bottom() - bounds.top()),
                    ),
                    theme.accent,
                )),
            )
        };

        EditorLinePrepaint {
            line: Some(shaped),
            cursor: cursor_quad,
            selection,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.editor.read(cx).focus_handle.clone();
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.editor.clone()),
            cx,
        );

        if let Some(selection) = prepaint.selection.take() {
            window.paint_quad(selection);
        }

        let line = prepaint.line.take().unwrap();
        line.paint(bounds.origin, window.line_height(), window, cx)
            .unwrap();

        if focus_handle.is_focused(window) {
            if let Some(cursor) = prepaint.cursor.take() {
                window.paint_quad(cursor);
            }
        }

        self.editor.update(cx, |editor, _cx| {
            editor.active_line_layout = Some(line);
            editor.active_line_bounds = Some(bounds);
        });
    }
}
