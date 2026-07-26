//! AI provider integration with streaming support

use crate::CoreError;
use crate::platform::HttpClient;
use crate::types::{AiConfig, AiProvider, ChatMessage, MessageRole, StreamEvent};
use serde::Serialize;

// Re-export pure parsers from codewire-types
pub use codewire_types::{parse_anthropic_sse_event, parse_openai_sse_event, process_sse_buffer};

/// Callback interface for streaming events
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait StreamCallback: Send + Sync {
    fn on_event(&self, event: StreamEvent);
}

/// AI client for chat completions
pub struct AiClient<H: HttpClient> {
    config: AiConfig,
    http_client: H,
}

impl<H: HttpClient> AiClient<H> {
    /// Create a new AI client
    pub fn new(config: AiConfig, http_client: H) -> Self {
        Self {
            config,
            http_client,
        }
    }

    /// Stream a message response from the AI provider
    pub async fn stream_message(
        &self,
        messages: Vec<ChatMessage>,
        callback: Box<dyn StreamCallback>,
    ) -> Result<(), CoreError> {
        match self.config.provider {
            AiProvider::Anthropic => self.stream_anthropic(messages, callback).await,
            AiProvider::OpenAi | AiProvider::OpenRouter => {
                self.stream_openai_compatible(messages, callback).await
            }
        }
    }

    /// Get the current configuration
    pub fn get_config(&self) -> AiConfig {
        self.config.clone()
    }

    /// Stream from Anthropic's Messages API
    async fn stream_anthropic(
        &self,
        messages: Vec<ChatMessage>,
        callback: Box<dyn StreamCallback>,
    ) -> Result<(), CoreError> {
        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or("https://api.anthropic.com");

        let api_messages: Vec<AnthropicMessage> = messages
            .into_iter()
            .filter(|m| !matches!(m.role, MessageRole::System))
            .map(|m| AnthropicMessage {
                role: match m.role {
                    MessageRole::User => "user".to_string(),
                    MessageRole::Assistant => "assistant".to_string(),
                    MessageRole::System => "user".to_string(),
                },
                content: m.content,
            })
            .collect();

        let request = AnthropicRequest {
            model: self.config.model.clone(),
            max_tokens: 4096,
            messages: api_messages,
            stream: true,
        };

        let body = serde_json::to_vec(&request)?;
        let headers = [
            ("x-api-key", self.config.api_key.as_str()),
            ("anthropic-version", "2023-06-01"),
            ("content-type", "application/json"),
        ];

        let (status, mut rx) = self
            .http_client
            .post_streaming(&format!("{}/v1/messages", base_url), &headers, &body)
            .await?;

        if !(200..300).contains(&status) {
            // Collect error body
            let mut error_body = Vec::new();
            while let Some(chunk) = rx.recv().await {
                if let Ok(data) = chunk {
                    error_body.extend_from_slice(&data);
                }
            }
            return Err(CoreError::Api {
                message: format!(
                    "Anthropic API error {}: {}",
                    status,
                    String::from_utf8_lossy(&error_body)
                ),
            });
        }

        let mut buffer = String::new();
        let mut full_content = String::new();

        while let Some(chunk) = rx.recv().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE events using pure parsing
            while let Some(event_end) = buffer.find("\n\n") {
                let event_data = buffer[..event_end].to_string();
                buffer = buffer[event_end + 2..].to_string();

                if let Some(token) = parse_anthropic_sse_event(&event_data) {
                    full_content.push_str(&token);
                    callback.on_event(StreamEvent::Token { text: token });
                }
            }
        }

        let response_message = ChatMessage {
            id: uuid::Uuid::new_v4().to_string(),
            role: MessageRole::Assistant,
            content: full_content,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        callback.on_event(StreamEvent::Done {
            message: response_message,
        });

        Ok(())
    }

    /// Stream from OpenAI-compatible APIs (OpenAI, OpenRouter, etc.)
    async fn stream_openai_compatible(
        &self,
        messages: Vec<ChatMessage>,
        callback: Box<dyn StreamCallback>,
    ) -> Result<(), CoreError> {
        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or(match self.config.provider {
                AiProvider::OpenAi => "https://api.openai.com",
                AiProvider::OpenRouter => "https://openrouter.ai/api",
                AiProvider::Anthropic => "https://api.anthropic.com",
            });

        let api_messages: Vec<OpenAiMessage> = messages
            .into_iter()
            .map(|m| OpenAiMessage {
                role: match m.role {
                    MessageRole::User => "user".to_string(),
                    MessageRole::Assistant => "assistant".to_string(),
                    MessageRole::System => "system".to_string(),
                },
                content: m.content,
            })
            .collect();

        let request = OpenAiRequest {
            model: self.config.model.clone(),
            messages: api_messages,
            stream: true,
        };

        let body = serde_json::to_vec(&request)?;
        let api_key_header = format!("Bearer {}", self.config.api_key);
        let headers = [
            ("Authorization", api_key_header.as_str()),
            ("content-type", "application/json"),
        ];

        let (status, mut rx) = self
            .http_client
            .post_streaming(
                &format!("{}/v1/chat/completions", base_url),
                &headers,
                &body,
            )
            .await?;

        if !(200..300).contains(&status) {
            let mut error_body = Vec::new();
            while let Some(chunk) = rx.recv().await {
                if let Ok(data) = chunk {
                    error_body.extend_from_slice(&data);
                }
            }
            return Err(CoreError::Api {
                message: format!(
                    "OpenAI API error {}: {}",
                    status,
                    String::from_utf8_lossy(&error_body)
                ),
            });
        }

        let mut buffer = String::new();
        let mut full_content = String::new();

        while let Some(chunk) = rx.recv().await {
            let chunk = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(event_end) = buffer.find("\n\n") {
                let event_data = buffer[..event_end].to_string();
                buffer = buffer[event_end + 2..].to_string();

                if let Some(token) = parse_openai_sse_event(&event_data) {
                    full_content.push_str(&token);
                    callback.on_event(StreamEvent::Token { text: token });
                }
            }
        }

        let response_message = ChatMessage {
            id: uuid::Uuid::new_v4().to_string(),
            role: MessageRole::Assistant,
            content: full_content,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        callback.on_event(StreamEvent::Done {
            message: response_message,
        });

        Ok(())
    }
}

// ============================================================================
// API Types (internal — request types only; SSE response parsing is in codewire-types)
// ============================================================================

// Anthropic API types
#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
    stream: bool,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

// OpenAI API types
#[derive(Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    stream: bool,
}

#[derive(Serialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

// SSE parser tests are in codewire-types::parsers
