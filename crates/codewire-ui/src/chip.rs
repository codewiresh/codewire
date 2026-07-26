//! Selectable chip/pill component for option groups

use crate::theme::Theme;
use gpui::{SharedString, div, prelude::*, px};

/// A selectable chip/pill for option groups.
/// Returns a Div -- caller MUST chain .id() then .on_click().
pub fn option_chip(label: impl Into<SharedString>, selected: bool) -> gpui::Div {
    let theme = Theme::dark();
    let hover_bg = gpui::hsla(0.0, 0.0, 0.22, 1.0);

    let base = div()
        .px_3()
        .py_1()
        .rounded(px(4.0))
        .text_size(px(11.0))
        .cursor_pointer()
        .border_1();

    if selected {
        base.bg(theme.accent)
            .border_color(theme.accent)
            .text_color(gpui::hsla(0.0, 0.0, 1.0, 1.0))
            .child(label.into())
    } else {
        base.bg(theme.surface)
            .border_color(theme.border)
            .text_color(theme.foreground)
            .hover(|s| s.bg(hover_bg))
            .child(label.into())
    }
}
