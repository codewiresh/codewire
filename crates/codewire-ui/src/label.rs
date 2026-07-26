//! Label helper

use gpui::{FontWeight, Hsla, SharedString, div, prelude::*};

/// Render a form field label (text-xs, medium weight).
pub fn label(text: impl Into<SharedString>, color: Hsla) -> impl IntoElement {
    div()
        .text_xs()
        .font_weight(FontWeight::MEDIUM)
        .text_color(color)
        .child(text.into())
}
