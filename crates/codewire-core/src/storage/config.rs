//! Configuration storage for app settings

use crate::CoreError;
use crate::platform::PersistentStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Manages persistent configuration storage, generic over storage backend
pub struct ConfigStorage<S: PersistentStorage> {
    storage: S,
}

impl<S: PersistentStorage> ConfigStorage<S> {
    /// Create a new config storage with a given backend
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Save the last used session for a workspace
    pub fn save_last_session(
        &self,
        workspace_id: String,
        session_name: String,
    ) -> Result<(), CoreError> {
        let mut settings = self.load_settings()?;
        settings.last_sessions.insert(workspace_id, session_name);
        self.save_settings(&settings)
    }

    /// Get the last used session for a workspace
    pub fn get_last_session(&self, workspace_id: String) -> Result<Option<String>, CoreError> {
        let settings = self.load_settings()?;
        Ok(settings.last_sessions.get(&workspace_id).cloned())
    }

    /// Load saved local project paths
    pub fn load_local_projects(&self) -> Result<Vec<String>, CoreError> {
        let settings = self.load_settings()?;
        Ok(settings.local_projects)
    }

    /// Save local project paths
    pub fn save_local_projects(&self, paths: Vec<String>) -> Result<(), CoreError> {
        let mut settings = self.load_settings()?;
        settings.local_projects = paths;
        self.save_settings(&settings)
    }

    /// Load settings from storage
    fn load_settings(&self) -> Result<AppSettings, CoreError> {
        match self.storage.read("settings.json")? {
            None => Ok(AppSettings::default()),
            Some(content) => match serde_json::from_str(&content) {
                Ok(s) => Ok(s),
                Err(e) => {
                    tracing::warn!("Failed to parse settings.json, using defaults: {}", e);
                    Ok(AppSettings::default())
                }
            },
        }
    }

    /// Save settings to storage
    fn save_settings(&self, settings: &AppSettings) -> Result<(), CoreError> {
        let content = serde_json::to_string_pretty(settings)?;
        self.storage.write("settings.json", &content)
    }
}

/// Application settings
#[derive(Serialize, Deserialize, Default)]
struct AppSettings {
    #[serde(default)]
    last_sessions: HashMap<String, String>,
    #[serde(default)]
    local_projects: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory persistent storage for tests
    struct MemoryPersistentStorage {
        data: Mutex<HashMap<String, String>>,
    }

    impl MemoryPersistentStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl PersistentStorage for MemoryPersistentStorage {
        fn read(&self, key: &str) -> Result<Option<String>, CoreError> {
            let data = self.data.lock().unwrap();
            Ok(data.get(key).cloned())
        }

        fn write(&self, key: &str, value: &str) -> Result<(), CoreError> {
            let mut data = self.data.lock().unwrap();
            data.insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), CoreError> {
            let mut data = self.data.lock().unwrap();
            data.remove(key);
            Ok(())
        }

        fn exists(&self, key: &str) -> bool {
            let data = self.data.lock().unwrap();
            data.contains_key(key)
        }
    }

    fn test_storage() -> ConfigStorage<MemoryPersistentStorage> {
        ConfigStorage::new(MemoryPersistentStorage::new())
    }

    #[test]
    fn test_save_and_get_last_session() {
        let storage = test_storage();

        let result = storage.get_last_session("workspace-1".to_string()).unwrap();
        assert!(result.is_none());

        storage
            .save_last_session("workspace-1".to_string(), "claude".to_string())
            .unwrap();

        let result = storage.get_last_session("workspace-1".to_string()).unwrap();
        assert_eq!(result, Some("claude".to_string()));

        storage
            .save_last_session("workspace-2".to_string(), "dev".to_string())
            .unwrap();

        assert_eq!(
            storage.get_last_session("workspace-1".to_string()).unwrap(),
            Some("claude".to_string())
        );
        assert_eq!(
            storage.get_last_session("workspace-2".to_string()).unwrap(),
            Some("dev".to_string())
        );

        storage
            .save_last_session("workspace-1".to_string(), "main".to_string())
            .unwrap();
        assert_eq!(
            storage.get_last_session("workspace-1".to_string()).unwrap(),
            Some("main".to_string())
        );
    }

    #[test]
    fn test_save_and_load_local_projects() {
        let storage = test_storage();

        assert!(storage.load_local_projects().unwrap().is_empty());

        let paths = vec![
            "/home/user/proj-a".to_string(),
            "/home/user/proj-b".to_string(),
        ];
        storage.save_local_projects(paths.clone()).unwrap();

        assert_eq!(storage.load_local_projects().unwrap(), paths);
    }
}
