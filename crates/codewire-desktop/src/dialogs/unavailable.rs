use crate::theme::Theme;
use codewire_ui::{modal_backdrop, modal_panel};
use gpui::{
    App, Context, EventEmitter, FocusHandle, Focusable, SharedString, Window, div, prelude::*, px,
    svg,
};

#[derive(Clone, Debug)]
pub struct UnavailableDialogDismissed;

/// Retained native interaction boundary for a platform action that has not
/// migrated yet. It fails visibly instead of redirecting to an old client.
pub struct UnavailableDialog {
    title: SharedString,
    detail: SharedString,
    focus_handle: FocusHandle,
}

impl UnavailableDialog {
    pub fn new(
        title: impl Into<SharedString>,
        detail: impl Into<SharedString>,
        cx: &mut Context<Self>,
    ) -> Self {
        Self {
            title: title.into(),
            detail: detail.into(),
            focus_handle: cx.focus_handle(),
        }
    }

    fn dismiss(&mut self, cx: &mut Context<Self>) {
        cx.emit(UnavailableDialogDismissed);
    }
}

impl EventEmitter<UnavailableDialogDismissed> for UnavailableDialog {}

impl Focusable for UnavailableDialog {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for UnavailableDialog {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        modal_backdrop().track_focus(&self.focus_handle(cx)).child(
            modal_panel(440.0)
                .gap(px(16.0))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(17.0))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(theme.foreground)
                                .child(self.title.clone()),
                        )
                        .child(
                            div()
                                .id("unavailable-dialog-close")
                                .p(px(4.0))
                                .rounded(px(4.0))
                                .cursor_pointer()
                                .hover(|style| style.bg(theme.background))
                                .on_click(cx.listener(|this, _, _, cx| this.dismiss(cx)))
                                .child(
                                    svg()
                                        .path("icons/close.svg")
                                        .size(px(16.0))
                                        .text_color(theme.muted),
                                ),
                        ),
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
                        .gap(px(7.0))
                        .child(
                            div()
                                .text_size(px(12.0))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(theme.status_needs_auth)
                                .child("Not available in this desktop migration slice"),
                        )
                        .child(
                            div()
                                .text_size(px(12.0))
                                .line_height(gpui::relative(1.45))
                                .text_color(theme.muted)
                                .child(self.detail.clone()),
                        ),
                )
                .child(
                    div().flex().justify_end().child(
                        div()
                            .id("unavailable-dialog-dismiss")
                            .px(px(14.0))
                            .py(px(7.0))
                            .rounded(px(5.0))
                            .bg(theme.accent)
                            .text_size(px(12.0))
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(gpui::hsla(0.0, 0.0, 1.0, 1.0))
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _, _, cx| this.dismiss(cx)))
                            .child("Done"),
                    ),
                ),
        )
    }
}
