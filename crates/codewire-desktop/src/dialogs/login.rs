use crate::theme::Theme;
use codewire_ui::{ButtonVariant, button, modal_backdrop, modal_panel};
use gpui::{Context, EventEmitter, SharedString, Window, div, prelude::*, px};

pub enum LoginDialogEvent {
    Cancelled,
}

/// Browser-owned sign-in progress shown while the OAuth PKCE callback waits.
pub struct LoginDialog {
    authorization_url: SharedString,
}

impl LoginDialog {
    pub fn new(authorization_url: impl Into<SharedString>, _cx: &mut Context<Self>) -> Self {
        Self {
            authorization_url: authorization_url.into(),
        }
    }
}

impl EventEmitter<LoginDialogEvent> for LoginDialog {}

impl Render for LoginDialog {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
                )
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap(px(8.0))
                        .child(
                            button("Cancel", ButtonVariant::Secondary)
                                .id("oauth-cancel")
                                .on_click(cx.listener(|_this, _, _, cx| {
                                    cx.emit(LoginDialogEvent::Cancelled);
                                })),
                        )
                        .child(
                            button("Open browser", ButtonVariant::Primary)
                                .id("oauth-open-browser")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    cx.open_url(this.authorization_url.as_ref());
                                })),
                        ),
                )
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(theme.muted)
                        .child("Press Escape to cancel."),
                ),
        )
    }
}
