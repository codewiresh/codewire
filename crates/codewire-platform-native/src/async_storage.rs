use codewire_core::{AsyncStorage, CoreError};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Async storage backed by JSONL files via `tokio::fs`
pub struct TokioAsyncStorage {
    base_dir: PathBuf,
}

impl TokioAsyncStorage {
    pub fn new() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".codewire")
            .join("history");
        Self { base_dir }
    }

    /// Create with a custom base directory (useful for testing)
    pub fn with_dir(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.base_dir.join(format!("{key}.jsonl"))
    }
}

impl Default for TokioAsyncStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncStorage for TokioAsyncStorage {
    async fn read_lines(&self, key: &str) -> Result<Vec<String>, CoreError> {
        let path = self.path_for(key);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = tokio::fs::read_to_string(&path).await?;
        Ok(content
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    async fn append(&self, key: &str, line: &str) -> Result<(), CoreError> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        file.write_all(format!("{line}\n").as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }

    async fn append_lines(&self, key: &str, lines: &[String]) -> Result<(), CoreError> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        for line in lines {
            file.write_all(format!("{line}\n").as_bytes()).await?;
        }
        file.flush().await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CoreError> {
        let path = self.path_for(key);
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, CoreError> {
        Ok(self.path_for(key).exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_append_and_read_lines() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokioAsyncStorage::with_dir(dir.path().to_path_buf());

        // Empty initially
        let lines = storage.read_lines("chat-1").await.unwrap();
        assert!(lines.is_empty());

        // Append single lines
        storage
            .append("chat-1", r#"{"role":"user"}"#)
            .await
            .unwrap();
        storage
            .append("chat-1", r#"{"role":"assistant"}"#)
            .await
            .unwrap();

        let lines = storage.read_lines("chat-1").await.unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], r#"{"role":"user"}"#);
        assert_eq!(lines[1], r#"{"role":"assistant"}"#);
    }

    #[tokio::test]
    async fn test_append_lines_batch() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokioAsyncStorage::with_dir(dir.path().to_path_buf());

        let batch = vec![
            "line1".to_string(),
            "line2".to_string(),
            "line3".to_string(),
        ];
        storage.append_lines("batch", &batch).await.unwrap();

        let lines = storage.read_lines("batch").await.unwrap();
        assert_eq!(lines, batch);
    }

    #[tokio::test]
    async fn test_delete_and_exists() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokioAsyncStorage::with_dir(dir.path().to_path_buf());

        assert!(!storage.exists("chat-2").await.unwrap());

        storage.append("chat-2", "test").await.unwrap();
        assert!(storage.exists("chat-2").await.unwrap());

        storage.delete("chat-2").await.unwrap();
        assert!(!storage.exists("chat-2").await.unwrap());
    }
}
