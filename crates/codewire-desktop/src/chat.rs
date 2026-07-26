//! Chat panel with message list and input

use crate::SendMessage;
use crate::input::TextInput;
use crate::theme::Theme;
use codewire_core::ai::{AiClient, StreamCallback};
use codewire_core::{AiConfig, AiProvider, ChatMessage, MessageRole, StreamEvent};
use codewire_platform_native::ReqwestHttpClient;
use gpui::{
    App, Context, Entity, FocusHandle, Focusable, SharedString, Window, div, prelude::*, px,
};
use std::sync::{Arc, Mutex};

/// Chat panel containing messages and input
pub struct ChatPanel {
    messages: Vec<ChatMessage>,
    input: Entity<TextInput>,
    focus_handle: FocusHandle,
    is_streaming: bool,
    current_response: String,
    ai_client: Option<Arc<AiClient<ReqwestHttpClient>>>,
}

impl ChatPanel {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let input = cx
            .new(|cx| TextInput::new("Type a message... (Set ANTHROPIC_API_KEY to enable AI)", cx));

        // Try to create AI client from environment
        let ai_client = std::env::var("ANTHROPIC_API_KEY").ok().map(|api_key| {
            Arc::new(AiClient::new(
                AiConfig {
                    provider: AiProvider::Anthropic,
                    api_key,
                    model: "claude-sonnet-4-20250514".into(),
                    base_url: None,
                },
                ReqwestHttpClient::new(),
            ))
        });

        // Welcome message
        let messages = vec![ChatMessage {
            id: "welcome".into(),
            role: MessageRole::Assistant,
            content: "Welcome to Codewire! I'm here to help you with coding. Ask me anything about your project.".into(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }];

        Self {
            messages,
            input,
            focus_handle: cx.focus_handle(),
            is_streaming: false,
            current_response: String::new(),
            ai_client,
        }
    }

    pub fn focus_input(&self, window: &mut Window, _cx: &mut Context<Self>) {
        let handle = self.input.read(_cx).focus_handle(_cx);
        window.focus(&handle);
    }

    fn send_message(&mut self, _: &SendMessage, _window: &mut Window, cx: &mut Context<Self>) {
        let content = self.input.read(cx).content().to_string();
        if content.trim().is_empty() {
            return;
        }

        // Add user message
        let user_message = ChatMessage {
            id: uuid::Uuid::new_v4().to_string(),
            role: MessageRole::User,
            content: content.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        self.messages.push(user_message);

        // Clear input
        self.input.update(cx, |input, cx| {
            input.clear(cx);
        });

        // Start streaming if we have an AI client
        if let Some(client) = &self.ai_client {
            self.is_streaming = true;
            self.current_response.clear();

            let messages = self.messages.clone();
            let client = client.clone();

            // Create a callback that updates via channel
            let response = Arc::new(Mutex::new(String::new()));
            let response_clone = response.clone();

            cx.spawn(async move |this, cx| {
                struct Callback {
                    response: Arc<Mutex<String>>,
                }

                impl StreamCallback for Callback {
                    fn on_event(&self, event: StreamEvent) {
                        match event {
                            StreamEvent::Token { text } => {
                                self.response.lock().unwrap().push_str(&text);
                            }
                            StreamEvent::Done { .. } => {}
                            StreamEvent::Error { message } => {
                                tracing::error!("Stream error: {}", message);
                            }
                            _ => {}
                        }
                    }
                }

                let callback = Box::new(Callback {
                    response: response_clone,
                });

                let result = client.stream_message(messages, callback).await;

                // Update UI with final response
                let final_response = response.lock().unwrap().clone();
                this.update(cx, |this, cx| {
                    this.is_streaming = false;

                    if result.is_ok() && !final_response.is_empty() {
                        this.messages.push(ChatMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            role: MessageRole::Assistant,
                            content: final_response,
                            timestamp: chrono::Utc::now().timestamp_millis() as u64,
                        });
                    } else if let Err(e) = result {
                        this.messages.push(ChatMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            role: MessageRole::Assistant,
                            content: format!("Error: {}", e),
                            timestamp: chrono::Utc::now().timestamp_millis() as u64,
                        });
                    }

                    cx.notify();
                })
                .ok();
            })
            .detach();
        } else {
            // No AI client - add a placeholder response
            self.messages.push(ChatMessage {
                id: uuid::Uuid::new_v4().to_string(),
                role: MessageRole::Assistant,
                content: "AI is not configured. Set ANTHROPIC_API_KEY environment variable.".into(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            });
        }

        cx.notify();
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
        let is_streaming = self.is_streaming;
        let current_response = self.current_response.clone();

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(theme.surface)
            .track_focus(&self.focus_handle(cx))
            .on_action(cx.listener(Self::send_message))
            .child(
                // Header
                div()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(theme.border)
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Chat"),
            )
            .child(
                // Messages area
                div()
                    .id("messages-scroll")
                    .flex_1()
                    .overflow_y_scroll()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .p_4()
                            .children(
                                self.messages
                                    .iter()
                                    .map(|msg| MessageView::new(msg.clone())),
                            )
                            .when(is_streaming, |d| {
                                d.child(MessageView::streaming(current_response))
                            }),
                    ),
            )
            .child(
                // Input area
                div()
                    .p_4()
                    .border_t_1()
                    .border_color(theme.border)
                    .key_context("ChatInput")
                    .child(self.input.clone()),
            )
    }
}

/// A single message in the chat
struct MessageView {
    message: ChatMessage,
    is_streaming: bool,
}

impl MessageView {
    fn new(message: ChatMessage) -> Self {
        Self {
            message,
            is_streaming: false,
        }
    }

    fn streaming(content: String) -> Self {
        Self {
            message: ChatMessage {
                id: "streaming".into(),
                role: MessageRole::Assistant,
                content,
                timestamp: 0,
            },
            is_streaming: true,
        }
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
                    .child(SharedString::from(self.message.content.clone()))
                    .when(self.is_streaming, |d| {
                        d.child(
                            gpui::div()
                                .w(px(8.0))
                                .h(px(16.0))
                                .bg(theme.accent)
                                .rounded_sm(),
                        )
                    }),
            )
    }
}
