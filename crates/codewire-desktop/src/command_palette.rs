//! Command Palette modal (Cmd+Shift+P) for discovering and invoking actions.
//!
//! Provides a centered modal overlay with text input and fuzzy-matched
//! action list with keybinding hints.

use crate::theme::Theme;
use gpui::{
    App, Context, ElementId, EventEmitter, FocusHandle, Focusable, SharedString, Window, actions,
    div, prelude::*, px,
};

actions!(command_palette, [DismissPalette]);

/// A registered action that can be invoked from the palette
#[derive(Clone, Debug)]
pub struct PaletteAction {
    /// Display name shown in the palette
    pub name: String,
    /// Optional keybinding hint (e.g., "Cmd+W")
    pub keybinding: Option<String>,
    /// Unique identifier for this action
    pub id: String,
}

/// Event emitted when an action is selected from the palette
#[derive(Clone, Debug)]
pub struct PaletteActionSelected {
    pub action_id: String,
}

impl EventEmitter<PaletteActionSelected> for CommandPalette {}

pub struct CommandPalette {
    visible: bool,
    query: String,
    /// All registered actions
    actions: Vec<PaletteAction>,
    /// Filtered actions based on query
    filtered: Vec<PaletteAction>,
    /// Currently highlighted result index
    selected_index: usize,
    focus_handle: FocusHandle,
}

impl CommandPalette {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let actions = Self::default_actions();
        let filtered = actions.clone();

        Self {
            visible: false,
            query: String::new(),
            actions,
            filtered,
            selected_index: 0,
            focus_handle: cx.focus_handle(),
        }
    }

    fn default_actions() -> Vec<PaletteAction> {
        vec![
            PaletteAction {
                name: "Split Right".into(),
                keybinding: Some("Cmd+D".into()),
                id: "split_right".into(),
            },
            PaletteAction {
                name: "Split Down".into(),
                keybinding: Some("Cmd+Shift+D".into()),
                id: "split_down".into(),
            },
            PaletteAction {
                name: "Close Tab".into(),
                keybinding: Some("Cmd+W".into()),
                id: "close_tab".into(),
            },
            PaletteAction {
                name: "Next Tab".into(),
                keybinding: Some("Cmd+Shift+]".into()),
                id: "next_tab".into(),
            },
            PaletteAction {
                name: "Previous Tab".into(),
                keybinding: Some("Cmd+Shift+[".into()),
                id: "prev_tab".into(),
            },
            PaletteAction {
                name: "Toggle Sidebar".into(),
                keybinding: Some("Cmd+B".into()),
                id: "toggle_sidebar".into(),
            },
            PaletteAction {
                name: "Quick Open File".into(),
                keybinding: Some("Cmd+P".into()),
                id: "quick_open".into(),
            },
            PaletteAction {
                name: "Save File".into(),
                keybinding: Some("Cmd+S".into()),
                id: "save_file".into(),
            },
            PaletteAction {
                name: "Undo".into(),
                keybinding: Some("Cmd+Z".into()),
                id: "undo".into(),
            },
            PaletteAction {
                name: "Redo".into(),
                keybinding: Some("Cmd+Shift+Z".into()),
                id: "redo".into(),
            },
            PaletteAction {
                name: "Select All".into(),
                keybinding: Some("Cmd+A".into()),
                id: "select_all".into(),
            },
            PaletteAction {
                name: "Copy".into(),
                keybinding: Some("Cmd+C".into()),
                id: "copy".into(),
            },
            PaletteAction {
                name: "Cut".into(),
                keybinding: Some("Cmd+X".into()),
                id: "cut".into(),
            },
            PaletteAction {
                name: "Paste".into(),
                keybinding: Some("Cmd+V".into()),
                id: "paste".into(),
            },
            PaletteAction {
                name: "Split Workspace Right".into(),
                keybinding: Some("Cmd+Alt+D".into()),
                id: "split_workspace_right".into(),
            },
            PaletteAction {
                name: "Close Workspace".into(),
                keybinding: Some("Cmd+Shift+W".into()),
                id: "close_workspace".into(),
            },
            PaletteAction {
                name: "Focus Chat".into(),
                keybinding: Some("Cmd+L".into()),
                id: "focus_input".into(),
            },
            PaletteAction {
                name: "Refresh Diff".into(),
                keybinding: Some("Cmd+R".into()),
                id: "refresh_diff".into(),
            },
            PaletteAction {
                name: "Refresh Explorer".into(),
                keybinding: Some("Cmd+R".into()),
                id: "refresh_explorer".into(),
            },
        ]
    }

    pub fn show(&mut self, cx: &mut Context<Self>) {
        self.visible = true;
        self.query.clear();
        self.selected_index = 0;
        self.filtered = self.actions.clone();
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

    fn apply_filter(&mut self) {
        let query = self.query.to_lowercase();
        if query.is_empty() {
            self.filtered = self.actions.clone();
        } else {
            self.filtered = self
                .actions
                .iter()
                .filter(|a| {
                    let name_lower = a.name.to_lowercase();
                    // Simple subsequence match
                    let mut qi = 0;
                    let query_chars: Vec<char> = query.chars().collect();
                    for ch in name_lower.chars() {
                        if qi < query_chars.len() && ch == query_chars[qi] {
                            qi += 1;
                        }
                    }
                    qi == query_chars.len()
                })
                .cloned()
                .collect();
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
        if let Some(action) = self.filtered.get(self.selected_index) {
            cx.emit(PaletteActionSelected {
                action_id: action.id.clone(),
            });
        }
        self.hide(cx);
    }

    fn dismiss(&mut self, _: &DismissPalette, _window: &mut Window, cx: &mut Context<Self>) {
        self.hide(cx);
    }
}

impl Focusable for CommandPalette {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for CommandPalette {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        if !self.visible {
            return div().into_any_element();
        }

        let query = self.query.clone();
        let selected_idx = self.selected_index;

        let visible_results: Vec<_> = self.filtered.iter().take(15).cloned().collect();

        let dismiss_bg = div()
            .id("palette-dismiss")
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
            .child(div().text_color(theme.muted).mr_2().child(">"))
            .child(if query.is_empty() {
                div().text_color(theme.muted).child("Type a command...")
            } else {
                div().child(query)
            });

        let results = div()
            .id("palette-results")
            .w_full()
            .max_h(px(400.0))
            .overflow_y_scroll()
            .children(visible_results.iter().enumerate().map(|(idx, action)| {
                let is_selected = idx == selected_idx;
                let action_id = action.id.clone();

                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "palette-{}",
                        idx
                    ))))
                    .w_full()
                    .h(px(28.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .bg(if is_selected {
                        theme.explorer_selected_bg
                    } else {
                        theme.surface
                    })
                    .cursor_pointer()
                    .hover(|s| s.bg(theme.hover))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.emit(PaletteActionSelected {
                            action_id: action_id.clone(),
                        });
                        this.hide(cx);
                    }))
                    // Action name
                    .child(
                        div()
                            .flex_1()
                            .text_size(px(13.0))
                            .text_color(theme.foreground)
                            .child(action.name.clone()),
                    )
                    // Keybinding hint
                    .when(action.keybinding.is_some(), |d| {
                        d.child(
                            div()
                                .text_size(px(11.0))
                                .text_color(theme.muted)
                                .child(action.keybinding.clone().unwrap_or_default()),
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
            .key_context("CommandPalette")
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
