use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use codewire_core::{CoreError, SecureStorage};

// ============================================================================
// Global vault cache — all tokens in a single keychain entry
// ============================================================================

/// In-memory cache of the vault contents, loaded once from keychain.
struct VaultCache {
    map: HashMap<String, String>,
    loaded: bool,
}

impl VaultCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            loaded: false,
        }
    }
}

static VAULT: LazyLock<Mutex<VaultCache>> = LazyLock::new(|| Mutex::new(VaultCache::new()));

const SERVICE: &str = "codewire";
const ACCOUNT: &str = "vault";

/// Read the single keychain entry and deserialize the JSON map.
fn load_from_keychain(service: &str, account: &str) -> Result<HashMap<String, String>, CoreError> {
    let entry = keyring::Entry::new(service, account).map_err(|e| CoreError::Keychain {
        message: e.to_string(),
    })?;
    match entry.get_password() {
        Ok(json) => serde_json::from_str(&json).map_err(|e| CoreError::Keychain {
            message: format!("corrupt vault data: {e}"),
        }),
        Err(keyring::Error::NoEntry) => Ok(HashMap::new()),
        Err(e) => Err(CoreError::Keychain {
            message: e.to_string(),
        }),
    }
}

/// Serialize the map and write it to the single keychain entry.
fn flush_to_keychain(
    service: &str,
    account: &str,
    map: &HashMap<String, String>,
) -> Result<(), CoreError> {
    let entry = keyring::Entry::new(service, account).map_err(|e| CoreError::Keychain {
        message: e.to_string(),
    })?;
    if map.is_empty() {
        // Delete the entry when there's nothing to store
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CoreError::Keychain {
                message: e.to_string(),
            }),
        }
    } else {
        let json = serde_json::to_string(map).map_err(|e| CoreError::Keychain {
            message: format!("failed to serialize vault: {e}"),
        })?;
        entry.set_password(&json).map_err(|e| CoreError::Keychain {
            message: e.to_string(),
        })
    }
}

// ============================================================================
// KeyringSecureStorage
// ============================================================================

/// Secure credential storage using the OS keychain.
///
/// The default instance uses a **single** keychain entry (service=`"codewire"`,
/// account=`"vault"`) containing a JSON map of all tokens. This avoids multiple
/// keychain prompts on macOS for unsigned dev builds.
///
/// Instances created via [`with_service`](Self::with_service) bypass the global
/// cache and use their own isolated vault entry, suitable for tests.
pub struct KeyringSecureStorage {
    /// `None` → use the global `VAULT` cache (production path).
    /// `Some(service)` → use a local vault entry (test path).
    custom_service: Option<String>,
}

impl KeyringSecureStorage {
    pub fn new() -> Self {
        Self {
            custom_service: None,
        }
    }

    /// Create with a custom service name (useful for testing).
    /// Bypasses the global vault cache — each instance is isolated.
    pub fn with_service(service: &str) -> Self {
        Self {
            custom_service: Some(service.to_string()),
        }
    }
}

impl Default for KeyringSecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for KeyringSecureStorage {
    fn store(&self, key: &str, value: &str) -> Result<(), CoreError> {
        if let Some(service) = &self.custom_service {
            // Test path: local vault, no global cache
            let mut map = load_from_keychain(service, ACCOUNT)?;
            map.insert(key.to_string(), value.to_string());
            flush_to_keychain(service, ACCOUNT, &map)
        } else {
            // Production path: global cache
            let mut cache = VAULT.lock().unwrap();
            if !cache.loaded {
                cache.map = load_from_keychain(SERVICE, ACCOUNT)?;
                cache.loaded = true;
            }
            cache.map.insert(key.to_string(), value.to_string());
            flush_to_keychain(SERVICE, ACCOUNT, &cache.map)
        }
    }

    fn retrieve(&self, key: &str) -> Result<Option<String>, CoreError> {
        if let Some(service) = &self.custom_service {
            let map = load_from_keychain(service, ACCOUNT)?;
            Ok(map.get(key).cloned())
        } else {
            let mut cache = VAULT.lock().unwrap();
            if !cache.loaded {
                cache.map = load_from_keychain(SERVICE, ACCOUNT)?;
                cache.loaded = true;
            }
            Ok(cache.map.get(key).cloned())
        }
    }

    fn delete(&self, key: &str) -> Result<(), CoreError> {
        if let Some(service) = &self.custom_service {
            let mut map = load_from_keychain(service, ACCOUNT)?;
            if map.remove(key).is_some() {
                flush_to_keychain(service, ACCOUNT, &map)?;
            }
            Ok(())
        } else {
            let mut cache = VAULT.lock().unwrap();
            if !cache.loaded {
                cache.map = load_from_keychain(SERVICE, ACCOUNT)?;
                cache.loaded = true;
            }
            if cache.map.remove(key).is_some() {
                flush_to_keychain(SERVICE, ACCOUNT, &cache.map)?;
            }
            Ok(())
        }
    }
}

// Note: Keyring tests require a real OS keychain and are not run in CI.
// To test locally: cargo test -p codewire-platform-native keyring -- --ignored
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires OS keychain access"]
    fn test_store_retrieve_delete() {
        let storage = KeyringSecureStorage::with_service("codewire-test");

        // Clean up first
        let _ = storage.delete("test-token");

        // Store
        storage.store("test-token", "secret123").unwrap();

        // Retrieve
        let val = storage.retrieve("test-token").unwrap();
        assert_eq!(val, Some("secret123".to_string()));

        // Delete
        storage.delete("test-token").unwrap();
        let val = storage.retrieve("test-token").unwrap();
        assert_eq!(val, None);
    }

    #[test]
    #[ignore = "requires OS keychain access"]
    fn test_multiple_keys_single_entry() {
        let storage = KeyringSecureStorage::with_service("codewire-test-multi");

        // Clean slate
        let _ = storage.delete("key-a");
        let _ = storage.delete("key-b");

        // Store two keys
        storage.store("key-a", "value-a").unwrap();
        storage.store("key-b", "value-b").unwrap();

        // Both retrievable
        assert_eq!(storage.retrieve("key-a").unwrap(), Some("value-a".into()));
        assert_eq!(storage.retrieve("key-b").unwrap(), Some("value-b".into()));

        // Delete one, other persists
        storage.delete("key-a").unwrap();
        assert_eq!(storage.retrieve("key-a").unwrap(), None);
        assert_eq!(storage.retrieve("key-b").unwrap(), Some("value-b".into()));

        // Cleanup
        storage.delete("key-b").unwrap();
    }

    #[test]
    fn test_retrieve_nonexistent() {
        let storage = KeyringSecureStorage::with_service("codewire-test-nonexist");
        // Should return None, not error (may fail on some platforms without keychain)
        let result = storage.retrieve("definitely-not-here");
        // On CI without keychain, this may error. That's acceptable.
        if let Ok(val) = result {
            assert_eq!(val, None);
        }
    }
}
