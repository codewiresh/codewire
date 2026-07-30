use crate::theme::Theme;
use codewire_ui::{modal_backdrop, modal_panel};
use gpui::{Context, Window, div, prelude::*, px};

/// Browser-owned sign-in progress shown while the OAuth PKCE callback waits.
pub struct LoginDialog;

impl LoginDialog {
    pub fn new(_cx: &mut Context<Self>) -> Self {
        Self
    }
}

impl Render for LoginDialog {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        modal_backdrop().child(
            modal_panel(440.0)
                .gap(px(14.0))
                .child(
                    div()
                        .text_size(px(17.0))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(theme.foreground)
                        .child("Sign in to Codewire"),
                )
                .child(
                    div()
                        .p(px(14.0))
                        .rounded(px(7.0))
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.background)
                        .flex()
                        .flex_col()
                        .gap(px(8.0))
                        .child(
                            div()
                                .text_size(px(13.0))
                                .text_color(theme.foreground)
                                .child("Continue in your system browser"),
                        )
                        .child(
                            div()
                                .text_size(px(12.0))
                                .line_height(gpui::relative(1.45))
                                .text_color(theme.muted)
                                .child(
                                    "Complete login, 2FA, or passkey verification there, then \
                                     return here. The desktop never receives your password.",
                                ),
                        ),
                )
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(theme.accent)
                        .child("Waiting for the secure OAuth callback…"),
                ),
        )
    }
}
