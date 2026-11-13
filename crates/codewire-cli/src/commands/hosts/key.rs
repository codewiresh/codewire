//! The host key and where it is kept (#3609, #4432): the OS keyring, or on
//! a Linux computer with no Secret Service a file only its user can read.

use std::path::{Path, PathBuf};

use codewire_protected_store::{
    FileProtectedStore, OsProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
    ProtectedValue,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// Where a host's key is kept. Chosen once, at enroll; the agent and `cw
/// host leave` use only the recorded one.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyStore {
    /// The OS keyring: Secret Service on Linux, the Keychain on macOS.
    #[default]
    Keyring,
    /// A file only this user can read, in a private directory beside the
    /// enrollment (Linux only).
    File,
}

/// The keyring entries holding host keys: one per enrollment, so two
/// configurations on one computer (say Dev and Production) never share one.
const HOST_KEY_ENTRY_PREFIX: &str = "host/ed25519/";
/// The private directory holding the key when it is kept in a file.
const KEY_DIRECTORY: &str = "host-key";

/// A fresh keyring entry name for a new enrollment.
pub(super) fn new_key_entry() -> String {
    format!("{HOST_KEY_ENTRY_PREFIX}{}", uuid::Uuid::new_v4())
}

pub(super) fn key_entry(name: &str) -> Result<ProtectedEntryId, ProtectedStoreError> {
    if !name.starts_with(HOST_KEY_ENTRY_PREFIX) {
        return Err(ProtectedStoreError::InvalidEntryId);
    }
    ProtectedEntryId::parse(name)
}

/// The open store an enrollment's key is in.
#[derive(Clone)]
pub(super) enum HostKeyStore {
    Keyring,
    File(FileProtectedStore),
}

impl HostKeyStore {
    pub(super) fn open(dir: &Path, store: KeyStore) -> Result<Self, ProtectedStoreError> {
        match store {
            KeyStore::Keyring => Ok(Self::Keyring),
            KeyStore::File => FileProtectedStore::new(key_directory(dir)).map(Self::File),
        }
    }

    fn store(&self) -> &dyn ProtectedStore {
        match self {
            Self::Keyring => &OsProtectedStore,
            Self::File(file) => file,
        }
    }
}

pub(super) fn key_directory(dir: &Path) -> PathBuf {
    dir.join(KEY_DIRECTORY)
}

/// Where the key is, in words, for enroll and `cw host status`.
pub(super) fn key_store_text(dir: &Path, store: KeyStore) -> String {
    match store {
        KeyStore::Keyring => "the OS keyring".to_owned(),
        KeyStore::File => format!("{}, readable only by you", key_directory(dir).display()),
    }
}

/// The store a new enrollment tries first, and the one to fall back to when
/// that store does not exist on this computer: a Linux computer with no
/// Secret Service at all keeps the key in a file (#4432). A keyring that
/// exists but is locked is not a reason to fall back.
pub(super) fn key_store_plan(choice: Option<KeyStore>) -> (KeyStore, Option<KeyStore>) {
    match choice {
        Some(store) => (store, None),
        None if cfg!(target_os = "linux") => (KeyStore::Keyring, Some(KeyStore::File)),
        None => (KeyStore::Keyring, None),
    }
}

pub(super) fn key_store_error(store: KeyStore, error: ProtectedStoreError) -> anyhow::Error {
    match (store, error) {
        (KeyStore::Keyring, ProtectedStoreError::AccessDenied) => anyhow::anyhow!(
            "the OS keyring is locked or inaccessible; unlock it (log in to this computer) and retry"
        ),
        (KeyStore::Keyring, ProtectedStoreError::Unavailable) => anyhow::anyhow!(
            "this computer has no OS keyring; on Linux, `cw host enroll --key-store file` keeps the key in a file only you can read"
        ),
        (KeyStore::Keyring, other) => anyhow::anyhow!("the OS keyring could not be used: {other}"),
        (KeyStore::File, other) => anyhow::anyhow!("the host key file could not be used: {other}"),
    }
}

/// Reads the host key, off the async runtime: the keyring calls block.
pub(super) async fn read_key(
    store: &HostKeyStore,
    entry: &str,
) -> Result<Option<SigningKey>, ProtectedStoreError> {
    let entry = key_entry(entry)?;
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        let Some(value) = store.store().get(&entry)? else {
            return Ok(None);
        };
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(value.expose_secret())
                .map_err(|_| ProtectedStoreError::CorruptEntry)?,
        );
        Ok(Some(SigningKey::from_bytes(&seed)))
    })
    .await
    .unwrap_or(Err(ProtectedStoreError::Unavailable))
}

pub(super) async fn store_key(
    store: &HostKeyStore,
    entry: &str,
    key: &SigningKey,
) -> Result<(), ProtectedStoreError> {
    let entry = key_entry(entry)?;
    let value = ProtectedValue::from_slice(key.as_bytes())?;
    let store = store.clone();
    tokio::task::spawn_blocking(move || store.store().put(&entry, &value))
        .await
        .unwrap_or(Err(ProtectedStoreError::Unavailable))
}

pub(super) async fn delete_key(
    store: &HostKeyStore,
    entry: &str,
) -> Result<(), ProtectedStoreError> {
    let entry = key_entry(entry)?;
    let store = store.clone();
    tokio::task::spawn_blocking(move || store.store().delete(&entry))
        .await
        .unwrap_or(Err(ProtectedStoreError::Unavailable))
}

/// Keeps a new enrollment's key where `choice` says, or by `key_store_plan`,
/// and returns where it went.
pub(super) async fn store_new_key(
    dir: &Path,
    choice: Option<KeyStore>,
    entry: &str,
    key: &SigningKey,
) -> anyhow::Result<KeyStore> {
    let (first, fallback) = key_store_plan(choice);
    if first == KeyStore::File {
        anyhow::ensure!(
            cfg!(target_os = "linux"),
            "`--key-store file` is for Linux; this computer keeps host keys in its OS keyring"
        );
    }
    let opened = HostKeyStore::open(dir, first).map_err(|error| key_store_error(first, error))?;
    let error = match store_key(&opened, entry, key).await {
        Ok(()) => return Ok(first),
        Err(error) => error,
    };
    match (error, fallback) {
        (ProtectedStoreError::Unavailable, Some(store)) => {
            let opened =
                HostKeyStore::open(dir, store).map_err(|error| key_store_error(store, error))?;
            store_key(&opened, entry, key)
                .await
                .map_err(|error| key_store_error(store, error))?;
            Ok(store)
        }
        (error, _) => Err(key_store_error(first, error)),
    }
}

pub(super) fn new_key() -> SigningKey {
    use rand::RngCore as _;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_key_tries_the_keyring_and_on_linux_falls_back_to_a_file() {
        let fallback = cfg!(target_os = "linux").then_some(KeyStore::File);
        assert_eq!(key_store_plan(None), (KeyStore::Keyring, fallback));
        // An explicit choice is final either way.
        assert_eq!(
            key_store_plan(Some(KeyStore::Keyring)),
            (KeyStore::Keyring, None)
        );
        assert_eq!(key_store_plan(Some(KeyStore::File)), (KeyStore::File, None));
    }

    #[test]
    fn a_missing_keyring_names_the_file_store_and_a_locked_one_asks_for_a_login() {
        let missing = key_store_error(KeyStore::Keyring, ProtectedStoreError::Unavailable);
        assert!(
            missing.to_string().contains("--key-store file"),
            "{missing}"
        );
        let locked = key_store_error(KeyStore::Keyring, ProtectedStoreError::AccessDenied);
        assert!(locked.to_string().contains("unlock it"), "{locked}");
        let file = key_store_error(KeyStore::File, ProtectedStoreError::Unavailable);
        assert!(file.to_string().starts_with("the host key file"), "{file}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_file_kept_key_is_private_reads_back_and_leaves_nothing() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        use super::super::ensure_private_dir;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("config");
        ensure_private_dir(&dir).unwrap();
        let key = new_key();
        let entry = new_key_entry();
        assert_eq!(
            store_new_key(&dir, Some(KeyStore::File), &entry, &key)
                .await
                .unwrap(),
            KeyStore::File
        );
        let store = HostKeyStore::open(&dir, KeyStore::File).unwrap();
        let read = read_key(&store, &entry).await.unwrap().unwrap();
        assert_eq!(read.to_bytes(), key.to_bytes());

        let directory = key_directory(&dir);
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&directory), 0o700);
        let files: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|file| file.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(mode(&files[0]), 0o600);
        assert!(
            !fs::read(&files[0]).unwrap().is_empty(),
            "the key file holds the key"
        );

        delete_key(&store, &entry).await.unwrap();
        assert!(read_key(&store, &entry).await.unwrap().is_none());
    }
}
