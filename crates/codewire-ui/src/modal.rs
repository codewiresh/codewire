//! Modal dialog helpers

use crate::theme::Theme;
use gpui::{div, prelude::*, px};

/// Create the modal backdrop overlay (dark semi-transparent fullscreen).
/// Caller chains .track_focus(), .on_key_down(), and .child(panel).
pub fn modal_backdrop() -> gpui::Div {
    div()
        .absolute()
        .inset_0()
        .font_family(".AppleSystemUIFont")
        .bg(gpui::hsla(0.0, 0.0, 0.0, 0.6))
        .flex()
        .items_center()
        .justify_center()
}

/// Create the modal dialog panel container.
/// Caller chains .child(header), .child(content), etc.
pub fn modal_panel(width: f32) -> gpui::Div {
    let theme = Theme::dark();
    div()
        .w(px(width))
        .max_h(px(640.0))
        .bg(gpui::hsla(0.0, 0.0, 0.11, 1.0))
        .border_1()
        .border_color(theme.border)
        .rounded(px(8.0))
        .p_4()
        .flex()
        .flex_col()
}
