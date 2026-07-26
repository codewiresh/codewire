//! Reusable dropdown component

use crate::theme::Theme;
use gpui::{
    AnchoredPositionMode, App, Context, ElementId, EventEmitter, FocusHandle, Focusable,
    SharedString, Window, anchored, deferred, div, point, prelude::*, px,
};

/// An item in a dropdown list.
#[derive(Clone, Debug)]
pub struct DropdownItem {
    pub id: String,
    pub label: String,
    pub description: Option<String>,
}

/// Event emitted when an item is selected.
#[derive(Clone, Debug)]
pub struct DropdownItemSelected {
    pub item: DropdownItem,
}

/// Event emitted when the dropdown opens (for mutual exclusion with other dropdowns).
#[derive(Clone, Debug)]
pub struct DropdownOpened;

/// Reusable dropdown component with floating list.
///
/// Dismiss is NOT handled by the component — parent must add a dismiss layer
/// checking `dropdown.read(cx).is_open()` and calling `dropdown.update(cx, |d, cx| d.close(cx))`.
pub struct Dropdown {
    items: Vec<DropdownItem>,
    selected_id: Option<String>,
    open: bool,
    placeholder: SharedString,
    list_width: f32,
    id_prefix: SharedString,
    focus_handle: FocusHandle,
}

impl EventEmitter<DropdownItemSelected> for Dropdown {}
impl EventEmitter<DropdownOpened> for Dropdown {}

impl Dropdown {
    pub fn new(
        id_prefix: impl Into<SharedString>,
        placeholder: impl Into<SharedString>,
        cx: &mut Context<Self>,
    ) -> Self {
        Self {
            items: Vec::new(),
            selected_id: None,
            open: false,
            placeholder: placeholder.into(),
            list_width: 448.0,
            id_prefix: id_prefix.into(),
            focus_handle: cx.focus_handle(),
        }
    }

    pub fn set_items(&mut self, items: Vec<DropdownItem>, cx: &mut Context<Self>) {
        self.items = items;
        cx.notify();
    }

    pub fn set_selected(&mut self, id: Option<String>, cx: &mut Context<Self>) {
        self.selected_id = id;
        cx.notify();
    }

    pub fn selected_id(&self) -> Option<&str> {
        self.selected_id.as_deref()
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn close(&mut self, cx: &mut Context<Self>) {
        self.open = false;
        cx.notify();
    }

    fn toggle(&mut self, cx: &mut Context<Self>) {
        self.open = !self.open;
        if self.open {
            cx.emit(DropdownOpened);
        }
        cx.notify();
    }

    fn select_item(&mut self, item: DropdownItem, cx: &mut Context<Self>) {
        self.selected_id = Some(item.id.clone());
        self.open = false;
        cx.emit(DropdownItemSelected { item });
        cx.notify();
    }

    fn render_list(&self, theme: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        let selected_id = self.selected_id.as_deref();
        let dropdown_hover = gpui::hsla(0.0, 0.0, 0.22, 1.0);

        let mut list = div()
            .id(ElementId::Name(SharedString::from(format!(
                "{}-list-scroll",
                self.id_prefix
            ))))
            .w(px(self.list_width))
            .flex()
            .flex_col()
            .max_h(px(200.0))
            .overflow_y_scroll()
            .border_1()
            .border_color(theme.border)
            .rounded(px(6.0))
            .bg(theme.surface)
            .shadow_lg()
            .font_family(".AppleSystemUIFont");

        if self.items.is_empty() {
            list = list.child(
                div()
                    .p_3()
                    .text_sm()
                    .text_color(theme.muted)
                    .child("No items"),
            );
        } else {
            for (idx, item) in self.items.iter().enumerate() {
                let is_selected = selected_id == Some(item.id.as_str());
                let item_clone = item.clone();
                let selected_bg = if is_selected {
                    dropdown_hover
                } else {
                    gpui::hsla(0.0, 0.0, 0.0, 0.0)
                };
                let text_color = if is_selected {
                    theme.accent
                } else {
                    theme.foreground
                };

                let mut row = div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "{}-item-{}",
                        self.id_prefix, idx
                    ))))
                    .px_3()
                    .py_2()
                    .bg(selected_bg)
                    .hover(|s| s.bg(dropdown_hover))
                    .cursor_pointer()
                    .when(idx > 0, |el| el.border_t_1().border_color(theme.border))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.select_item(item_clone.clone(), cx);
                    }))
                    .child(
                        div()
                            .text_sm()
                            .text_color(text_color)
                            .child(SharedString::from(item.label.clone())),
                    );

                if let Some(ref desc) = item.description {
                    if !desc.is_empty() {
                        row =
                            row.child(div().text_xs().text_color(theme.muted).child(desc.clone()));
                    }
                }

                list = list.child(row);
            }
        }

        list.into_any_element()
    }
}

impl Focusable for Dropdown {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for Dropdown {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();
        let is_open = self.open;

        // Determine display label
        let selected_label = self
            .selected_id
            .as_ref()
            .and_then(|id| self.items.iter().find(|item| &item.id == id))
            .map(|item| item.label.clone())
            .unwrap_or_else(|| self.placeholder.to_string());

        let has_selection = self.selected_id.is_some();
        let chevron = if is_open { "\u{25B4}" } else { "\u{25BE}" }; // ▴ / ▾

        // Trigger + floating list wrapper
        let mut trigger_wrapper = div().relative().child(
            div()
                .id(ElementId::Name(SharedString::from(format!(
                    "{}-trigger",
                    self.id_prefix
                ))))
                .px_3()
                .py_2()
                .bg(theme.background)
                .border_1()
                .border_color(if is_open { theme.accent } else { theme.border })
                .rounded(px(6.0))
                .hover(|s| s.border_color(theme.accent))
                .cursor_pointer()
                .on_click(cx.listener(|this, _, _, cx| {
                    this.toggle(cx);
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_sm()
                                .text_color(if has_selection {
                                    theme.foreground
                                } else {
                                    theme.muted
                                })
                                .child(selected_label),
                        )
                        .child(div().text_xs().text_color(theme.muted).child(chevron)),
                ),
        );

        // Floating dropdown list
        if is_open {
            trigger_wrapper = trigger_wrapper.child(
                deferred(
                    anchored()
                        .position_mode(AnchoredPositionMode::Local)
                        .snap_to_window()
                        .offset(point(px(0.0), px(2.0)))
                        .child(self.render_list(&theme, cx)),
                )
                .with_priority(1),
            );
        }

        trigger_wrapper
    }
}
