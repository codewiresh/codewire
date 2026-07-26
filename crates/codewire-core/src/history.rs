//! Chat history persistence using JSONL format
//!
//! Each workspace has its own history stored via the AsyncStorage trait.
//! This format allows for:
//! - Append-only writes (no rewriting the entire file)
//! - Self-healing when corrupted entries are encountered
//! - Easy debugging and inspection

use crate::CoreError;
use crate::platform::AsyncStorage;
use crate::types::ChatMessage;

/// Manages chat history for a workspace, generic over storage backend
pub struct ChatHistory<S: AsyncStorage> {
    workspace_id: String,
    storage_key: String,
    storage: S,
}

impl<S: AsyncStorage> ChatHistory<S> {
    /// Create a new chat history manager
    ///
    /// # Arguments
    /// * `workspace_id` - Unique identifier for the workspace
    /// * `base_path` - Base path prefix for storage keys (e.g., "sessions")
    /// * `storage` - The async storage backend
    pub fn new(workspace_id: String, base_path: String, storage: S) -> Self {
        let storage_key = format!("{}/{}/chat.jsonl", base_path, workspace_id);
        Self {
            workspace_id,
            storage_key,
            storage,
        }
    }

    /// Load all messages from history
    ///
    /// Corrupted entries are silently skipped (self-healing behavior).
    pub async fn load_messages(&self) -> Result<Vec<ChatMessage>, CoreError> {
        if !self.storage.exists(&self.storage_key).await? {
            return Ok(Vec::new());
        }

        let lines = self.storage.read_lines(&self.storage_key).await?;
        let mut messages = Vec::new();

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<ChatMessage>(&line) {
                Ok(message) => messages.push(message),
                Err(e) => {
                    tracing::warn!(
                        "Skipping corrupted history entry in workspace {}: {}",
                        self.workspace_id,
                        e
                    );
                }
            }
        }

        Ok(messages)
    }

    /// Append a message to history
    pub async fn append_message(&self, message: ChatMessage) -> Result<(), CoreError> {
        let line = serde_json::to_string(&message)?;
        self.storage.append(&self.storage_key, &line).await?;

        tracing::debug!(
            "Appended message {} to workspace {} history",
            message.id,
            self.workspace_id
        );

        Ok(())
    }

    /// Append multiple messages to history
    pub async fn append_messages(&self, messages: Vec<ChatMessage>) -> Result<(), CoreError> {
        if messages.is_empty() {
            return Ok(());
        }

        let lines: Result<Vec<String>, _> = messages
            .iter()
            .map(|m| serde_json::to_string(m).map_err(CoreError::from))
            .collect();

        self.storage
            .append_lines(&self.storage_key, &lines?)
            .await?;

        tracing::debug!(
            "Appended {} messages to workspace {} history",
            messages.len(),
            self.workspace_id
        );

        Ok(())
    }

    /// Clear all history for the workspace
    pub async fn clear(&self) -> Result<(), CoreError> {
        if self.storage.exists(&self.storage_key).await? {
            self.storage.delete(&self.storage_key).await?;
            tracing::info!("Cleared history for workspace {}", self.workspace_id);
        }
        Ok(())
    }

    /// Get the workspace ID
    pub fn workspace_id(&self) -> String {
        self.workspace_id.clone()
    }

    /// Get the storage key
    pub fn storage_key(&self) -> String {
        self.storage_key.clone()
    }

    /// Get the number of messages in history
    pub async fn message_count(&self) -> Result<u64, CoreError> {
        if !self.storage.exists(&self.storage_key).await? {
            return Ok(0);
        }

        let lines = self.storage.read_lines(&self.storage_key).await?;
        let count = lines
            .iter()
            .filter(|line| {
                !line.trim().is_empty() && serde_json::from_str::<ChatMessage>(line).is_ok()
            })
            .count() as u64;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MessageRole;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory async storage for tests
    struct MemoryStorage {
        data: Mutex<HashMap<String, Vec<String>>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl AsyncStorage for MemoryStorage {
        async fn read_lines(&self, key: &str) -> Result<Vec<String>, CoreError> {
            let data = self.data.lock().unwrap();
            Ok(data.get(key).cloned().unwrap_or_default())
        }

        async fn append(&self, key: &str, line: &str) -> Result<(), CoreError> {
            let mut data = self.data.lock().unwrap();
            data.entry(key.to_string())
                .or_default()
                .push(line.to_string());
            Ok(())
        }

        async fn append_lines(&self, key: &str, lines: &[String]) -> Result<(), CoreError> {
            let mut data = self.data.lock().unwrap();
            let entry = data.entry(key.to_string()).or_default();
            entry.extend(lines.iter().cloned());
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), CoreError> {
            let mut data = self.data.lock().unwrap();
            data.remove(key);
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool, CoreError> {
            let data = self.data.lock().unwrap();
            Ok(data.contains_key(key))
        }
    }

    fn create_test_message(content: &str, role: MessageRole) -> ChatMessage {
        ChatMessage {
            id: uuid::Uuid::new_v4().to_string(),
            role,
            content: content.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    #[tokio::test]
    async fn test_empty_history() {
        let storage = MemoryStorage::new();
        let history = ChatHistory::new(
            "test-workspace".to_string(),
            "sessions".to_string(),
            storage,
        );

        let messages = history.load_messages().await.unwrap();
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_append_and_load() {
        let storage = MemoryStorage::new();
        let history = ChatHistory::new(
            "test-workspace".to_string(),
            "sessions".to_string(),
            storage,
        );

        let msg1 = create_test_message("Hello", MessageRole::User);
        let msg2 = create_test_message("Hi there!", MessageRole::Assistant);

        history.append_message(msg1.clone()).await.unwrap();
        history.append_message(msg2.clone()).await.unwrap();

        let messages = history.load_messages().await.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, "Hello");
        assert_eq!(messages[1].content, "Hi there!");
    }

    #[tokio::test]
    async fn test_self_healing_corrupted_entries() {
        let storage = MemoryStorage::new();

        // Pre-populate with mix of valid and corrupted entries
        let valid_msg = create_test_message("Valid message", MessageRole::User);
        let valid_json = serde_json::to_string(&valid_msg).unwrap();
        let valid_msg2 = create_test_message("Another valid", MessageRole::Assistant);
        let valid_json2 = serde_json::to_string(&valid_msg2).unwrap();

        {
            let mut data = storage.data.lock().unwrap();
            data.insert(
                "sessions/test-workspace/chat.jsonl".to_string(),
                vec![valid_json, "{invalid json}".to_string(), valid_json2],
            );
        }

        let history = ChatHistory::new(
            "test-workspace".to_string(),
            "sessions".to_string(),
            storage,
        );

        let messages = history.load_messages().await.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, "Valid message");
        assert_eq!(messages[1].content, "Another valid");
    }

    #[tokio::test]
    async fn test_clear() {
        let storage = MemoryStorage::new();
        let history = ChatHistory::new(
            "test-workspace".to_string(),
            "sessions".to_string(),
            storage,
        );

        let msg = create_test_message("Test", MessageRole::User);
        history.append_message(msg).await.unwrap();

        let messages = history.load_messages().await.unwrap();
        assert_eq!(messages.len(), 1);

        history.clear().await.unwrap();

        let messages = history.load_messages().await.unwrap();
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_message_count() {
        let storage = MemoryStorage::new();
        let history = ChatHistory::new(
            "test-workspace".to_string(),
            "sessions".to_string(),
            storage,
        );

        assert_eq!(history.message_count().await.unwrap(), 0);

        history
            .append_message(create_test_message("1", MessageRole::User))
            .await
            .unwrap();
        history
            .append_message(create_test_message("2", MessageRole::Assistant))
            .await
            .unwrap();
        history
            .append_message(create_test_message("3", MessageRole::User))
            .await
            .unwrap();

        assert_eq!(history.message_count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_append_messages_batch() {
        let storage = MemoryStorage::new();
        let history = ChatHistory::new(
            "test-workspace".to_string(),
            "sessions".to_string(),
            storage,
        );

        let messages = vec![
            create_test_message("1", MessageRole::User),
            create_test_message("2", MessageRole::Assistant),
            create_test_message("3", MessageRole::User),
        ];

        history.append_messages(messages).await.unwrap();

        let loaded = history.load_messages().await.unwrap();
        assert_eq!(loaded.len(), 3);
    }
}
