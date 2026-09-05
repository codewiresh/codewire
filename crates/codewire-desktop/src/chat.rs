//! Chat panel shell awaiting a credential-broker adapter.

use crate::theme::Theme;
use codewire_types::{ChatMessage, MessageRole};
use gpui::{App, Context, FocusHandle, Focusable, SharedString, Window, div, prelude::*};

/// Chat remains visible in the desktop layout, but cannot submit content until
/// it has a credential-blind broker adapter.
pub struct ChatPanel {
    messages: Vec<ChatMessage>,
    focus_handle: FocusHandle,
}

impl ChatPanel {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            messages: vec![ChatMessage {
                id: "broker-unconfigured".into(),
                role: MessageRole::Assistant,
                content: "Chat is unavailable until a credential-broker adapter is configured."
                    .into(),
                timestamp: 0,
            }],
            focus_handle: cx.focus_handle(),
        }
    }
}

impl Focusable for ChatPanel {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for ChatPanel {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(theme.surface)
            .track_focus(&self.focus_handle(cx))
            .child(
                div()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(theme.border)
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Chat"),
            )
            .child(
                div().id("messages-scroll").flex_1().child(
                    div().flex().flex_col().gap_3().p_4().children(
                        self.messages
                            .iter()
                            .map(|message| MessageView::new(message.clone())),
                    ),
                ),
            )
            .child(
                div()
                    .p_4()
                    .border_t_1()
                    .border_color(theme.border)
                    .text_sm()
                    .text_color(theme.muted)
                    .child("Credential-broker chat adapter not configured"),
            )
    }
}

/// A single message in the chat shell.
struct MessageView {
    message: ChatMessage,
}

impl MessageView {
    fn new(message: ChatMessage) -> Self {
        Self { message }
    }
}

impl IntoElement for MessageView {
    type Element = gpui::Div;

    fn into_element(self) -> Self::Element {
        let theme = Theme::dark();

        let (label, label_color) = match self.message.role {
            MessageRole::User => ("You", theme.user_message),
            MessageRole::Assistant => ("Assistant", theme.assistant_message),
            MessageRole::System => ("System", theme.muted),
        };

        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(label_color)
                    .child(SharedString::from(label)),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(theme.foreground)
                    .child(SharedString::from(self.message.content)),
            )
    }
}
