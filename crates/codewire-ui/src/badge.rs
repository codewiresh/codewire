//! Badge and indicator helpers

use gpui::{Hsla, div, prelude::*, px, svg};

/// Small colored circle indicator (6x6).
pub fn status_dot(color: Hsla) -> impl IntoElement {
    div()
        .w(px(6.0))
        .h(px(6.0))
        .rounded_full()
        .bg(color)
        .flex_shrink_0()
}

/// Left-side blue selection indicator bar (3px wide, absolute positioned).
pub fn selection_bar(is_selected: bool) -> impl IntoElement {
    let blue_400 = gpui::hsla(213.0 / 360.0, 0.94, 0.68, 1.0);
    div()
        .absolute()
        .left_0()
        .top_0()
        .bottom_0()
        .w(px(3.0))
        .bg(if is_selected {
            blue_400
        } else {
            gpui::hsla(0.0, 0.0, 0.0, 0.0)
        })
}

/// Expandable chevron indicator (right when collapsed, down when expanded).
pub fn chevron(expanded: bool, color: Hsla) -> impl IntoElement {
    svg()
        .path(if expanded {
            "icons/chevron-down.svg"
        } else {
            "icons/chevron-right.svg"
        })
        .size(px(12.0))
        .text_color(color)
        .flex_shrink_0()
}
