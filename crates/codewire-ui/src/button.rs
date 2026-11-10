//! Button component

use crate::theme::Theme;
use gpui::{SharedString, div, prelude::*, px};

#[derive(Clone, Copy, PartialEq)]
pub enum ButtonVariant {
    /// Accent bg, dark text, opacity hover
    Primary,
    /// Surface bg, normal text, bg hover
    Secondary,
    /// Transparent bg, shows bg on hover
    Ghost,
}

/// Create a styled button. Returns a Div — caller MUST chain .id() then .on_click().
pub fn button(label: impl Into<SharedString>, variant: ButtonVariant) -> gpui::Div {
    let theme = Theme::dark();
    let base = div()
        .px_3()
        .py_1()
        .rounded(px(4.0))
        .text_sm()
        .cursor_pointer();

    match variant {
        ButtonVariant::Primary => base
            .bg(theme.accent)
            .text_color(theme.background)
            .hover_style(|s| s.opacity(0.9))
            .child(label.into()),
        ButtonVariant::Secondary => base
            .bg(theme.surface)
            .text_color(theme.foreground)
            .hover_style(|s| s.bg(gpui::hsla(0.0, 0.0, 0.22, 1.0)))
            .child(label.into()),
        ButtonVariant::Ghost => base
            .bg(gpui::hsla(0.0, 0.0, 0.0, 0.0))
            .text_color(theme.foreground)
            .hover_style(|s| s.bg(gpui::hsla(0.0, 0.0, 0.22, 1.0)))
            .child(label.into()),
    }
}
