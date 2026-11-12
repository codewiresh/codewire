use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use codewire_access::{
    AccessProfileId, AccessProfileName, CapabilitySlot, CredentialAuthKind, CredentialId,
    CredentialPlaceholder, EnvironmentAccessBinding, EnvironmentId, ProviderId,
    builtin_provider_catalog,
};
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreBackend, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue,
};
use tempfile::TempDir;

use crate::{
    AuthorityProtectedStore, LocalCredentialAuthority, LocalCredentialError, NewCredential,
};

/// One labelled in-memory backend; clones share entries and faults.
#[derive(Clone, Default)]
struct Backend {
    state: Arc<Mutex<BackendState>>,
}

#[derive(Default)]
struct BackendState {
    entries: BTreeMap<String, Vec<u8>>,
    fail_get: Option<ProtectedStoreError>,
    fail_put: Option<ProtectedStoreError>,
    fail_delete: Option<ProtectedStoreError>,
    corrupt_reads: bool,
    calls: usize,
}

impl Backend {
    fn with<T>(&self, operation: impl FnOnce(&mut BackendState) -> T) -> T {
        operation(&mut self.state.lock().unwrap())
    }

    fn values(&self) -> Vec<Vec<u8>> {
        self.with(|state| state.entries.values().cloned().collect())
    }

    fn calls(&self) -> usize {
        self.with(|state| state.calls)
    }
}

impl ProtectedStore for Backend {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.with(|state| {
            state.calls += 1;
            if let Some(error) = state.fail_get {
                return Err(error);
            }
            let corrupt = state.corrupt_reads;
            state
                .entries
                .get(id.expose_reference())
                .map(|value| {
                    let mut value = value.clone();
                    if corrupt {
                        value.push(0);
                    }
                    ProtectedValue::new(value)
                })
                .transpose()
        })
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        self.with(|state| {
            state.calls += 1;
            if let Some(error) = state.fail_put {
                return Err(error);
            }
            state.entries.insert(
                id.expose_reference().to_owned(),
                value.expose_secret().to_vec(),
            );
            Ok(())
        })
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.with(|state| {
            state.calls += 1;
            if let Some(error) = state.fail_delete {
                return Err(error);
            }
            state.entries.remove(id.expose_reference());
            Ok(())
        })
    }
}

/// One in-memory store per recorded location, created on first use.
struct Fixture {
    _directory: TempDir,
    root: std::path::PathBuf,
    stores: Arc<Mutex<BTreeMap<String, Backend>>>,
    opened: Arc<Mutex<Vec<AuthorityProtectedStore>>>,
}

fn store(backend: ProtectedStoreBackend) -> AuthorityProtectedStore {
    AuthorityProtectedStore {
        backend,
        keychain: None,
    }
}

const LEGACY: ProtectedStoreBackend = match ProtectedStoreBackend::platform_default() {
    Some(backend) => backend,
    None => ProtectedStoreBackend::SecretService,
};

fn other(backend: ProtectedStoreBackend) -> ProtectedStoreBackend {
    if backend == ProtectedStoreBackend::File {
        ProtectedStoreBackend::Keychain
    } else {
        ProtectedStoreBackend::File
    }
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("authority");
        Self {
            _directory: directory,
            root,
            stores: Arc::default(),
            opened: Arc::default(),
        }
    }

    fn located(&self, store: &AuthorityProtectedStore) -> Backend {
        self.stores
            .lock()
            .unwrap()
            .entry(store.to_record())
            .or_default()
            .clone()
    }

    fn backend(&self, backend: ProtectedStoreBackend) -> Backend {
        self.located(&store(backend))
    }

    fn all_stores(&self) -> Vec<(String, Backend)> {
        self.stores
            .lock()
            .unwrap()
            .iter()
            .map(|(record, store)| (record.clone(), store.clone()))
            .collect()
    }

    /// Open without the backend record, as an authority from before it.
    fn open_legacy(&self) -> LocalCredentialAuthority<Backend> {
        LocalCredentialAuthority::open(&self.root, self.backend(LEGACY), builtin_provider_catalog())
            .unwrap()
    }

    fn open(
        &self,
        backend: ProtectedStoreBackend,
    ) -> Result<LocalCredentialAuthority<Backend>, LocalCredentialError> {
        self.open_store(&store(backend))
    }

    /// The test stores are keyed by backend; `opened` records every
    /// location the authority asked for besides the selected one.
    fn open_store(
        &self,
        selected: &AuthorityProtectedStore,
    ) -> Result<LocalCredentialAuthority<Backend>, LocalCredentialError> {
        let stores = Arc::clone(&self.stores);
        let opened = Arc::clone(&self.opened);
        let open = move |store: &AuthorityProtectedStore| {
            opened.lock().unwrap().push(store.clone());
            let located = stores
                .lock()
                .unwrap()
                .entry(store.to_record())
                .or_default()
                .clone();
            Ok(Box::new(located) as Box<dyn ProtectedStore>)
        };
        LocalCredentialAuthority::open_with_backend(
            &self.root,
            self.located(selected),
            builtin_provider_catalog(),
            selected,
            &open,
        )
    }

    fn metadata(&self, key: &str) -> Option<String> {
        let connection = rusqlite::Connection::open(self.root.join(crate::DATABASE_FILE)).unwrap();
        connection
            .query_row(
                "SELECT value FROM authority_metadata WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .ok()
    }
}

fn store_values(authority: &LocalCredentialAuthority<Backend>) {
    authority
        .add_credential(
            NewCredential {
                provider: ProviderId::parse("openai").unwrap(),
                authentication_kind: CredentialAuthKind::ApiKey,
                display_name: "work-openai".into(),
                account_hint: None,
                expires_at_unix: None,
            },
            ProtectedValue::from_slice(b"sk-synthetic-provider").unwrap(),
        )
        .unwrap();
    authority
        .set_user_workload_secret(
            "APP_TOKEN",
            ProtectedValue::from_slice(b"synthetic-application-secret").unwrap(),
        )
        .unwrap();
}

fn sorted(mut values: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    values.sort();
    values
}

fn synthetic_values() -> Vec<Vec<u8>> {
    sorted(vec![
        b"sk-synthetic-provider".to_vec(),
        b"synthetic-application-secret".to_vec(),
    ])
}

#[test]
fn a_new_authority_records_its_backend_without_touching_any_store() {
    let fixture = Fixture::new();
    let selected = other(LEGACY);
    let authority = fixture.open(selected).unwrap();
    assert_eq!(authority.protected_store_identity(), Some(&store(selected)));
    drop(authority);
    assert_eq!(
        fixture.metadata("store_backend").as_deref(),
        Some(selected.as_str())
    );
    assert!(
        fixture
            .all_stores()
            .iter()
            .all(|(_, store)| store.calls() == 0)
    );
}

#[test]
fn a_legacy_database_keeps_its_platform_default_values_in_place() {
    let fixture = Fixture::new();
    store_values(&fixture.open_legacy());
    assert_eq!(fixture.metadata("store_backend"), None);

    drop(fixture.open(LEGACY).unwrap());
    assert_eq!(
        fixture.metadata("store_backend").as_deref(),
        Some(LEGACY.as_str())
    );
    assert_eq!(sorted(fixture.backend(LEGACY).values()), synthetic_values());
    assert!(
        fixture
            .all_stores()
            .iter()
            .filter(|(record, _)| record != LEGACY.as_str())
            .all(|(_, store)| store.calls() == 0)
    );
}

#[test]
fn switching_moves_every_exact_entry_then_retires_the_old_copies() {
    let fixture = Fixture::new();
    let first = other(LEGACY);
    store_values(&fixture.open(LEGACY).unwrap());

    let authority = fixture.open(first).unwrap();
    assert!(fixture.backend(LEGACY).values().is_empty());
    assert_eq!(sorted(fixture.backend(first).values()), synthetic_values());
    let secrets = authority.list_user_workload_secrets().unwrap();
    assert_eq!(secrets.len(), 1);
    drop(authority);
    assert_eq!(
        fixture.metadata("store_backend").as_deref(),
        Some(first.as_str())
    );
    assert_eq!(
        fixture.metadata(&format!("store_backend_retiring/{LEGACY}")),
        None
    );

    // Switching back moves them again.
    drop(fixture.open(LEGACY).unwrap());
    assert!(fixture.backend(first).values().is_empty());
    assert_eq!(sorted(fixture.backend(LEGACY).values()), synthetic_values());
}

#[test]
fn a_failed_switch_changes_nothing_and_reports_the_store_error() {
    let fixture = Fixture::new();
    let target = other(LEGACY);
    store_values(&fixture.open(LEGACY).unwrap());

    for (fault, expected) in [
        (0, ProtectedStoreError::AccessDenied),
        (1, ProtectedStoreError::TimedOut),
        (2, ProtectedStoreError::CorruptEntry),
    ] {
        match fault {
            0 => fixture
                .backend(LEGACY)
                .with(|state| state.fail_get = Some(expected)),
            1 => fixture
                .backend(target)
                .with(|state| state.fail_put = Some(expected)),
            _ => fixture
                .backend(target)
                .with(|state| state.corrupt_reads = true),
        }
        assert_eq!(
            fixture.open(target).err(),
            Some(LocalCredentialError::ProtectedStoreSwitch(expected))
        );
        assert!(fixture.backend(target).values().is_empty(), "{fault}");
        assert_eq!(sorted(fixture.backend(LEGACY).values()), synthetic_values());
        assert_eq!(
            fixture.metadata("store_backend").as_deref(),
            Some(LEGACY.as_str())
        );
        for (_, backend) in fixture.all_stores() {
            backend.with(|state| {
                state.fail_get = None;
                state.fail_put = None;
                state.corrupt_reads = false;
            });
        }
    }

    drop(fixture.open(target).unwrap());
    assert_eq!(sorted(fixture.backend(target).values()), synthetic_values());
}

#[test]
fn undeleted_old_copies_are_retried_and_block_only_a_switch_back() {
    let fixture = Fixture::new();
    let target = other(LEGACY);
    store_values(&fixture.open(LEGACY).unwrap());
    fixture
        .backend(LEGACY)
        .with(|state| state.fail_delete = Some(ProtectedStoreError::Unavailable));

    drop(fixture.open(target).unwrap());
    assert_eq!(sorted(fixture.backend(target).values()), synthetic_values());
    assert_eq!(sorted(fixture.backend(LEGACY).values()), synthetic_values());
    let marker = fixture
        .metadata(&format!("store_backend_retiring/{LEGACY}"))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<String>>(&marker).unwrap().len(),
        2
    );

    // Still failing: the selected backend serves; switching back is refused.
    drop(fixture.open(target).unwrap());
    assert_eq!(
        fixture.open(LEGACY).err(),
        Some(LocalCredentialError::ProtectedStoreSwitch(
            ProtectedStoreError::Unavailable
        ))
    );
    assert_eq!(sorted(fixture.backend(target).values()), synthetic_values());

    fixture
        .backend(LEGACY)
        .with(|state| state.fail_delete = None);
    drop(fixture.open(target).unwrap());
    assert!(fixture.backend(LEGACY).values().is_empty());
    assert_eq!(
        fixture.metadata(&format!("store_backend_retiring/{LEGACY}")),
        None
    );
}

#[test]
fn store_records_round_trip_and_keep_a_keychain_only_for_the_keychain_backend() {
    for record in [
        "secret-service",
        "keychain",
        "file",
        "keychain:/private/tmp/synthetic.keychain-db",
    ] {
        let parsed = AuthorityProtectedStore::from_record(record).unwrap();
        assert_eq!(parsed.to_record(), record);
    }
    for record in [
        "",
        "keyring",
        "file:/private/tmp/synthetic.keychain-db",
        "keychain:relative.keychain-db",
    ] {
        assert_eq!(
            AuthorityProtectedStore::from_record(record),
            None,
            "{record}"
        );
    }
}

#[test]
fn a_previous_store_is_opened_at_its_recorded_location_not_the_configured_one() {
    let fixture = Fixture::new();
    let explicit = AuthorityProtectedStore {
        backend: ProtectedStoreBackend::Keychain,
        keychain: Some("/synthetic/throwaway.keychain-db".into()),
    };
    store_values(&fixture.open_store(&explicit).unwrap());
    assert_eq!(
        fixture.metadata("store_backend").as_deref(),
        Some("keychain:/synthetic/throwaway.keychain-db")
    );
    fixture.opened.lock().unwrap().clear();

    drop(fixture.open(ProtectedStoreBackend::File).unwrap());
    assert_eq!(
        *fixture.opened.lock().unwrap(),
        [explicit.clone(), explicit.clone()]
    );
    assert_eq!(
        sorted(fixture.backend(ProtectedStoreBackend::File).values()),
        synthetic_values()
    );
    assert!(fixture.located(&explicit).values().is_empty());
    assert!(fixture.backend(ProtectedStoreBackend::Keychain).calls() == 0);
}

#[test]
fn another_keychain_location_is_a_store_switch() {
    let fixture = Fixture::new();
    let first = AuthorityProtectedStore {
        backend: ProtectedStoreBackend::Keychain,
        keychain: Some("/synthetic/first.keychain-db".into()),
    };
    let second = AuthorityProtectedStore {
        backend: ProtectedStoreBackend::Keychain,
        keychain: Some("/synthetic/second.keychain-db".into()),
    };
    store_values(&fixture.open_store(&first).unwrap());
    fixture.opened.lock().unwrap().clear();
    drop(fixture.open_store(&second).unwrap());
    assert_eq!(
        *fixture.opened.lock().unwrap(),
        [first.clone(), first.clone()]
    );
    assert_eq!(
        fixture.metadata("store_backend").as_deref(),
        Some("keychain:/synthetic/second.keychain-db")
    );
    assert!(fixture.located(&first).values().is_empty());
    assert_eq!(
        sorted(fixture.located(&second).values()),
        synthetic_values()
    );
}

/// The real file store and a throwaway keychain (synthetic password; the
/// login keychain is never named, unlocked or written).
#[cfg(target_os = "macos")]
mod macos {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use codewire_protected_store::{FileProtectedStore, KeychainProtectedStore};

    use super::*;
    use crate::AuthorityProtectedStore;

    const SECURITY: &str = "/usr/bin/security";
    const SYNTHETIC_PASSWORD: &str = "synthetic-test-keychain-password";

    struct ThrowawayKeychain(PathBuf);

    impl ThrowawayKeychain {
        fn create(directory: &Path) -> Self {
            let path = directory.join("codewire-test.keychain-db");
            let path_text = path.to_str().unwrap();
            for arguments in [
                vec!["create-keychain", "-p", SYNTHETIC_PASSWORD, path_text],
                vec!["set-keychain-settings", path_text],
                vec!["unlock-keychain", "-p", SYNTHETIC_PASSWORD, path_text],
            ] {
                let status = Command::new(SECURITY)
                    .args(&arguments)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success(), "{}", arguments[0]);
            }
            Self(path)
        }
    }

    impl Drop for ThrowawayKeychain {
        fn drop(&mut self) {
            let _ = Command::new(SECURITY)
                .arg("delete-keychain")
                .arg(&self.0)
                .stderr(Stdio::null())
                .status();
        }
    }

    fn entries(root: &Path) -> Vec<ProtectedEntryId> {
        let connection = rusqlite::Connection::open(root.join(crate::DATABASE_FILE)).unwrap();
        let mut statement = connection
            .prepare(
                "SELECT protected_entry_id FROM credentials
                 UNION SELECT protected_entry_id FROM workload_secrets",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|entry| ProtectedEntryId::parse(entry.unwrap()).unwrap())
            .collect()
    }

    fn values(store: &dyn ProtectedStore, entries: &[ProtectedEntryId]) -> Vec<Option<Vec<u8>>> {
        let mut values = entries
            .iter()
            .map(|id| {
                store
                    .get(id)
                    .unwrap()
                    .map(|value| value.expose_secret().to_vec())
            })
            .collect::<Vec<_>>();
        values.sort();
        values
    }

    #[test]
    fn values_move_between_the_file_store_and_a_throwaway_keychain() {
        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let keychain = ThrowawayKeychain::create(&directory);
        let root = directory.join("credentials-v1");
        let file = AuthorityProtectedStore {
            backend: ProtectedStoreBackend::File,
            keychain: None,
        };
        let keychain_store = AuthorityProtectedStore {
            backend: ProtectedStoreBackend::Keychain,
            keychain: Some(keychain.0.clone()),
        };
        let open = |selection: &AuthorityProtectedStore| {
            LocalCredentialAuthority::open_selected(&root, selection, builtin_provider_catalog())
                .unwrap()
        };

        let authority = open(&file);
        assert_eq!(authority.protected_store_identity(), Some(&file));
        authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "work-openai".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"sk-synthetic-provider").unwrap(),
            )
            .unwrap();
        let large = vec![b'v'; 20_000];
        authority
            .set_user_workload_secret("APP_TOKEN", ProtectedValue::from_slice(&large).unwrap())
            .unwrap();
        drop(authority);

        let ids = entries(&root);
        let files = FileProtectedStore::new(root.join(crate::FILE_STORE_DIRECTORY)).unwrap();
        let items = KeychainProtectedStore::with_keychain(keychain.0.clone()).unwrap();
        let expected = {
            let mut expected = vec![Some(b"sk-synthetic-provider".to_vec()), Some(large)];
            expected.sort();
            expected
        };
        assert_eq!(values(&files, &ids), expected);
        assert_eq!(values(&items, &ids), vec![None, None]);

        let authority = open(&keychain_store);
        assert_eq!(authority.protected_store_identity(), Some(&keychain_store));
        drop(authority);
        assert_eq!(values(&items, &ids), expected);
        assert_eq!(values(&files, &ids), vec![None, None]);
        assert_eq!(
            std::fs::read_dir(files.directory()).unwrap().count(),
            0,
            "no file copy remains"
        );

        drop(open(&file));
        assert_eq!(values(&files, &ids), expected);
        assert_eq!(values(&items, &ids), vec![None, None]);
    }
}

/// An environment bound to a profile that selects one new OpenAI credential
/// of `authority` in the OpenAI slot, for its placeholders (#3999).
struct PlaceholderEnvironment {
    credential_id: CredentialId,
    profile_id: AccessProfileId,
    binding: EnvironmentAccessBinding,
}

impl PlaceholderEnvironment {
    fn bind(authority: &LocalCredentialAuthority<Backend>) -> Self {
        let credential_id = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "placeholder-openai".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"sk-synthetic-placeholder").unwrap(),
            )
            .unwrap()
            .metadata
            .id;
        let profile = authority
            .create_profile(
                AccessProfileName::parse("placeholder").unwrap(),
                BTreeMap::from([(CapabilitySlot::openai(), credential_id.clone())]),
            )
            .unwrap()
            .profile;
        let binding = EnvironmentAccessBinding {
            environment_id: EnvironmentId::parse("environment-switch").unwrap(),
            profile_id: profile.id.clone(),
            profile_revision: profile.revision,
        };
        authority
            .create_environment_access_binding(binding.clone())
            .unwrap();
        Self {
            credential_id,
            profile_id: profile.id,
            binding,
        }
    }

    fn placeholder(&self, authority: &LocalCredentialAuthority<Backend>) -> CredentialPlaceholder {
        authority
            .environment_credential_placeholder(
                &self.binding.environment_id,
                3,
                &CapabilitySlot::openai(),
                &self.credential_id,
                Some(&self.binding),
            )
            .unwrap()
    }

    /// Delete the binding, the profile and the credential, so the root keeps
    /// no value but its placeholder key.
    fn delete(self, authority: &LocalCredentialAuthority<Backend>) {
        authority
            .delete_environment_access_binding(
                &self.binding.environment_id,
                &self.profile_id,
                self.binding.profile_revision,
            )
            .unwrap();
        authority.delete_profile(&self.profile_id).unwrap();
        authority.delete_credential(&self.credential_id).unwrap();
    }
}

impl Fixture {
    /// Another authority root on the same stores, as another HOME or
    /// credential root of the same OS user has.
    fn sharing_stores(&self) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("authority");
        Self {
            _directory: directory,
            root,
            stores: Arc::clone(&self.stores),
            opened: Arc::default(),
        }
    }

    /// This root's placeholder key entry, named by the ID its metadata
    /// keeps.
    fn placeholder_key_entry(&self) -> ProtectedEntryId {
        let authority_id = self.metadata("authority_id").unwrap();
        ProtectedEntryId::parse(format!("local/authority/{authority_id}/placeholder-key-v1"))
            .unwrap()
    }
}

impl Backend {
    fn value(&self, id: &ProtectedEntryId) -> Option<Vec<u8>> {
        self.with(|state| state.entries.get(id.expose_reference()).cloned())
    }
}

/// The placeholder key moves with the values it keys placeholders for, so
/// every placeholder is the same after a switch, and no copy stays behind
/// (#3999).
#[test]
fn switching_moves_the_placeholder_key_with_the_values() {
    let fixture = Fixture::new();
    let target = other(LEGACY);
    let authority = fixture.open(LEGACY).unwrap();
    store_values(&authority);
    let environment = PlaceholderEnvironment::bind(&authority);
    let before = environment.placeholder(&authority);
    drop(authority);
    assert_eq!(fixture.backend(LEGACY).values().len(), 4);

    let authority = fixture.open(target).unwrap();
    assert!(fixture.backend(LEGACY).values().is_empty());
    assert_eq!(fixture.backend(target).values().len(), 4);
    assert!(environment.placeholder(&authority).ct_eq(&before));
}

/// Authority roots of one OS user share its protected store. Each keeps its
/// own placeholder key there, through restarts, and a switch moves only its
/// own, even when the root has no other value left (#3999).
#[test]
fn each_root_keeps_and_moves_only_its_own_placeholder_key() {
    let first = Fixture::new();
    let second = first.sharing_stores();
    let target = other(LEGACY);
    let legacy = first.backend(LEGACY);

    let authority = first.open(LEGACY).unwrap();
    store_values(&authority);
    let first_environment = PlaceholderEnvironment::bind(&authority);
    let first_placeholder = first_environment.placeholder(&authority);
    drop(authority);
    let authority = second.open(LEGACY).unwrap();
    let second_environment = PlaceholderEnvironment::bind(&authority);
    let second_placeholder = second_environment.placeholder(&authority);
    drop(authority);

    let first_key = first.placeholder_key_entry();
    let second_key = second.placeholder_key_entry();
    assert!(first_key != second_key, "two roots share a key entry");
    let first_key_value = legacy.value(&first_key).unwrap();
    let second_key_value = legacy.value(&second_key).unwrap();
    assert!(first_key_value != second_key_value, "two roots share a key");

    // A restart of each, in turn, keeps both roots' placeholders and keys.
    for _ in 0..2 {
        let authority = first.open(LEGACY).unwrap();
        assert!(
            first_environment
                .placeholder(&authority)
                .ct_eq(&first_placeholder)
        );
        drop(authority);
        let authority = second.open(LEGACY).unwrap();
        assert!(
            second_environment
                .placeholder(&authority)
                .ct_eq(&second_placeholder)
        );
        drop(authority);
    }
    assert!(legacy.value(&first_key).as_ref() == Some(&first_key_value));
    assert!(legacy.value(&second_key).as_ref() == Some(&second_key_value));

    // The second root keeps only its key, then moves to another store: the
    // key moves, and nothing of the first root does.
    second_environment.delete(&second.open(LEGACY).unwrap());
    let first_values = sorted(
        legacy
            .values()
            .into_iter()
            .filter(|value| *value != second_key_value)
            .collect(),
    );
    assert_eq!(first_values.len(), 4);
    drop(second.open(target).unwrap());
    assert_eq!(legacy.value(&second_key), None);
    let moved = second.backend(target);
    assert_eq!(moved.values().len(), 1);
    assert!(moved.value(&second_key).as_ref() == Some(&second_key_value));
    assert_eq!(sorted(legacy.values()), first_values);

    let authority = first.open(LEGACY).unwrap();
    assert!(
        first_environment
            .placeholder(&authority)
            .ct_eq(&first_placeholder)
    );
}
