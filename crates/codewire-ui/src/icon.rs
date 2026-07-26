//! SVG icon helpers

use crate::theme::Theme;
use gpui::{Div, Hsla, div, prelude::*, px, svg};

/// Render an SVG icon at a given size and color.
/// text_color is set directly on the svg (required for GPUI SVG rendering).
pub fn icon(path: &'static str, size: f32, color: Hsla) -> impl IntoElement {
    svg()
        .path(path)
        .size(px(size))
        .text_color(color)
        .flex_shrink_0()
}

/// Clickable icon button with hover effects.
///
/// Returns a Div (not Stateful) — caller must chain `.id("...")` then `.on_click(...)`.
/// Color is set directly on the SVG element (GPUI requires this).
pub fn icon_button(path: &'static str, size: f32, color: Hsla, theme: &Theme) -> Div {
    div()
        .w(px(20.0))
        .h(px(20.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(3.0))
        .cursor_pointer()
        .flex_shrink_0()
        .hover(|s| s.bg(theme.hover).text_color(theme.foreground))
        .child(
            svg()
                .path(path)
                .size(px(size))
                .text_color(color)
                .flex_shrink_0(),
        )
}
