use codewire_core::{CoreError, PersistentStorage};
use std::path::PathBuf;

/// Filesystem-based persistent storage using `~/.codewire/` directory
pub struct FsPersistentStorage {
    base_dir: PathBuf,
}

impl FsPersistentStorage {
    pub fn new() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".codewire");
        Self { base_dir }
    }

    /// Create with a custom base directory (useful for testing)
    pub fn with_dir(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Return the default base directory (`~/.codewire/`).
    pub fn base_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".codewire")
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.base_dir.join(key)
    }
}

impl Default for FsPersistentStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentStorage for FsPersistentStorage {
    fn read(&self, key: &str) -> Result<Option<String>, CoreError> {
        let path = self.path_for(key);
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(Some(content))
    }

    fn write(&self, key: &str, value: &str) -> Result<(), CoreError> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, value)?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), CoreError> {
        let path = self.path_for(key);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn exists(&self, key: &str) -> bool {
        self.path_for(key).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_delete() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsPersistentStorage::with_dir(dir.path().to_path_buf());

        // Initially doesn't exist
        assert!(!storage.exists("config.json"));
        assert_eq!(storage.read("config.json").unwrap(), None);

        // Write
        storage.write("config.json", r#"{"key":"val"}"#).unwrap();
        assert!(storage.exists("config.json"));
        assert_eq!(
            storage.read("config.json").unwrap(),
            Some(r#"{"key":"val"}"#.to_string())
        );

        // Delete
        storage.delete("config.json").unwrap();
        assert!(!storage.exists("config.json"));
    }

    #[test]
    fn test_nested_keys() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsPersistentStorage::with_dir(dir.path().to_path_buf());

        storage.write("providers/codewire.json", "{}").unwrap();
        assert!(storage.exists("providers/codewire.json"));
        assert_eq!(
            storage.read("providers/codewire.json").unwrap(),
            Some("{}".to_string())
        );
    }

    #[test]
    fn test_delete_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsPersistentStorage::with_dir(dir.path().to_path_buf());
        // Should not error
        storage.delete("nonexistent").unwrap();
    }
}
