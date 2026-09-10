use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use codewire_access::builtin_provider_catalog;
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
};
use codewire_workload_secrets::ProjectionRecipient;
use tempfile::TempDir;

use super::*;

mod composition;

#[derive(Clone, Default)]
struct ObservedStore {
    inner: Arc<EphemeralProtectedStore>,
    reads: Arc<Mutex<Vec<ProtectedEntryId>>>,
    denied: Arc<Mutex<bool>>,
    block_until_ms: Arc<AtomicU64>,
}

impl ProtectedStore for ObservedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        self.inner.persistence()
    }
    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.reads.lock().unwrap().push(id.clone());
        while unix_millis().unwrap() < self.block_until_ms.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if *self.denied.lock().unwrap() {
            return Err(ProtectedStoreError::AccessDenied);
        }
        self.inner.get(id)
    }
    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        self.inner.put(id, value)
    }
    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.inner.delete(id)
    }
}

fn fixture() -> (
    TempDir,
    LocalCredentialAuthority<ObservedStore>,
    ObservedStore,
    Uuid,
) {
    let temp = TempDir::new().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = ObservedStore::default();
    let authority = LocalCredentialAuthority::open(
        &temp.path().join("authority"),
        store.clone(),
        builtin_provider_catalog(),
    )
    .unwrap();
    let project = authority.create_secret_project("development").unwrap();
    authority
        .set_project_workload_secret(
            project.id,
            "SHARED",
            ProtectedValue::from_slice(b"project-value").unwrap(),
        )
        .unwrap();
    authority
        .set_user_workload_secret("SHARED", ProtectedValue::from_slice(b"user-value").unwrap())
        .unwrap();
    authority
        .set_user_workload_secret(
            "OVERRIDDEN",
            ProtectedValue::from_slice(b"must-not-read").unwrap(),
        )
        .unwrap();
    store.reads.lock().unwrap().clear();
    (temp, authority, store, project.id)
}

fn context() -> ProjectionContext {
    ProjectionContext {
        environment_id: [1; 16],
        operation_generation: 1,
        selection_sha256: [2; 32],
        deadline_unix_ms: unix_millis().unwrap() + 30_000,
    }
}

fn selection(project_id: Uuid) -> LocalLaunchSecretSelection {
    LocalLaunchSecretSelection {
        project_id: Some(project_id),
        user: true,
        overridden_keys: BTreeSet::from(["OVERRIDDEN".into()]),
        reserved_keys: BTreeSet::new(),
    }
}

fn user_entry(authority: &LocalCredentialAuthority<ObservedStore>, key: &str) -> ProtectedEntryId {
    let connection = authority.connection().unwrap();
    crate::workload_secret::load_secret_by_key(&connection, SecretScope::User, key)
        .unwrap()
        .unwrap()
        .protected_entry_id
}

#[test]
fn only_winning_selected_values_are_read_and_response_is_recipient_bound() {
    let (_temp, authority, store, project_id) = fixture();
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let encrypted = authority
        .seal_workload_projection(&selection(project_id), &expected, recipient.public_key())
        .unwrap();
    assert_eq!(
        *store.reads.lock().unwrap(),
        [user_entry(&authority, "SHARED")]
    );
    let opened = recipient
        .open(&encrypted, &expected, unix_millis().unwrap())
        .unwrap();
    assert_eq!(
        opened.entries().collect::<Vec<_>>(),
        [("SHARED", "user-value")]
    );
}

#[test]
fn no_selection_and_fully_shadowed_selection_read_no_material_even_when_store_denies() {
    let (_temp, authority, store, project_id) = fixture();
    *store.denied.lock().unwrap() = true;
    let mut shadowed = selection(project_id);
    shadowed.overridden_keys.insert("SHARED".into());
    for selected in [LocalLaunchSecretSelection::default(), shadowed] {
        let recipient = ProjectionRecipient::new();
        let expected = context();
        let encrypted = authority
            .seal_workload_projection(&selected, &expected, recipient.public_key())
            .unwrap();
        assert_eq!(
            recipient
                .open(&encrypted, &expected, unix_millis().unwrap())
                .unwrap()
                .entries()
                .len(),
            0
        );
    }
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn denied_or_missing_winner_never_falls_back_to_project_material() {
    let (_temp, authority, store, project_id) = fixture();
    let expected = user_entry(&authority, "SHARED");
    for denied in [true, false] {
        *store.denied.lock().unwrap() = denied;
        if !denied {
            store.delete(&expected).unwrap();
        }
        let recipient = ProjectionRecipient::new();
        assert!(
            authority
                .seal_workload_projection(
                    &selection(project_id),
                    &context(),
                    recipient.public_key()
                )
                .is_err()
        );
        assert_eq!(
            store.reads.lock().unwrap().as_slice(),
            std::slice::from_ref(&expected),
        );
        store.reads.lock().unwrap().clear();
    }
}

#[test]
fn nonready_winner_does_not_disappear_into_a_lower_priority_source() {
    let (_temp, authority, store, project_id) = fixture();
    authority.connection().unwrap().execute("UPDATE workload_secrets SET material_state = 'pending_write' WHERE scope_kind = 'user' AND key = 'SHARED'", []).unwrap();
    let recipient = ProjectionRecipient::new();
    assert_eq!(
        authority
            .seal_workload_projection(&selection(project_id), &context(), recipient.public_key())
            .unwrap_err(),
        LocalCredentialError::WorkloadSecretMaterialMissing
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn exact_project_id_never_falls_back_to_a_recreated_name() {
    let (_temp, authority, store, project_id) = fixture();
    authority.delete_secret_project(project_id).unwrap();
    let replacement = authority.create_secret_project("development").unwrap();
    assert_ne!(replacement.id, project_id);
    store.reads.lock().unwrap().clear();
    let recipient = ProjectionRecipient::new();
    assert_eq!(
        authority
            .seal_workload_projection(&selection(project_id), &context(), recipient.public_key())
            .unwrap_err(),
        LocalCredentialError::SecretProjectNotFound
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn reserved_routing_key_collision_and_expired_context_fail_before_reads() {
    let (_temp, authority, store, project_id) = fixture();
    let mut selected = selection(project_id);
    selected.reserved_keys.insert("SHARED".into());
    let recipient = ProjectionRecipient::new();
    assert!(
        authority
            .seal_workload_projection(&selected, &context(), recipient.public_key())
            .is_err()
    );
    let mut expired = context();
    expired.deadline_unix_ms = 1;
    assert!(
        authority
            .seal_workload_projection(&selection(project_id), &expired, recipient.public_key())
            .is_err()
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn secret_rotation_is_seen_on_next_projection_not_in_an_existing_result() {
    let (_temp, authority, _store, project_id) = fixture();
    let recipient = ProjectionRecipient::new();
    let expected = context();
    let first = authority
        .seal_workload_projection(&selection(project_id), &expected, recipient.public_key())
        .unwrap();
    authority
        .set_user_workload_secret(
            "SHARED",
            ProtectedValue::from_slice(b"rotated-value").unwrap(),
        )
        .unwrap();
    assert_eq!(
        recipient
            .open(&first, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .next(),
        Some(("SHARED", "user-value"))
    );
    let recipient = ProjectionRecipient::new();
    let second = authority
        .seal_workload_projection(&selection(project_id), &expected, recipient.public_key())
        .unwrap();
    assert_eq!(
        recipient
            .open(&second, &expected, unix_millis().unwrap())
            .unwrap()
            .entries()
            .next(),
        Some(("SHARED", "rotated-value"))
    );
}

#[test]
fn too_many_selected_keys_fail_before_any_protected_read() {
    let (_temp, authority, store, _) = fixture();
    for i in 0..MAX_WORKLOAD_SECRETS {
        authority
            .set_user_workload_secret(
                &format!("KEY_{i:03}"),
                ProtectedValue::from_slice(b"synthetic").unwrap(),
            )
            .unwrap();
    }
    store.reads.lock().unwrap().clear();
    assert!(
        authority
            .inventory_workload_projection(&LocalLaunchSecretSelection {
                user: true,
                ..Default::default()
            })
            .is_err()
    );
    assert!(store.reads.lock().unwrap().is_empty());
    assert!(
        authority
            .seal_workload_projection(
                &LocalLaunchSecretSelection {
                    user: true,
                    ..Default::default()
                },
                &context(),
                ProjectionRecipient::new().public_key()
            )
            .is_err()
    );
    assert!(store.reads.lock().unwrap().is_empty());
}

#[test]
fn aggregate_size_limit_stops_further_material_reads() {
    let (_temp, authority, store, project_id) = fixture();
    for i in 0..5 {
        authority
            .set_project_workload_secret(
                project_id,
                &format!("LARGE_{i}"),
                ProtectedValue::new(
                    vec![b'x'; codewire_workload_secrets::MAX_WORKLOAD_SECRET_VALUE_BYTES],
                )
                .unwrap(),
            )
            .unwrap();
    }
    store.reads.lock().unwrap().clear();
    let selected = LocalLaunchSecretSelection {
        project_id: Some(project_id),
        ..Default::default()
    };
    assert!(
        authority
            .seal_workload_projection(
                &selected,
                &context(),
                ProjectionRecipient::new().public_key()
            )
            .is_err()
    );
    assert_eq!(store.reads.lock().unwrap().len(), 4);
}

#[test]
fn expired_blocking_read_cannot_publish_a_fresh_projection() {
    let (_temp, authority, store, project_id) = fixture();
    let mut expected = context();
    expected.deadline_unix_ms = unix_millis().unwrap() + 200;
    store
        .block_until_ms
        .store(expected.deadline_unix_ms, Ordering::Relaxed);
    assert!(
        authority
            .seal_workload_projection(
                &selection(project_id),
                &expected,
                ProjectionRecipient::new().public_key()
            )
            .is_err()
    );
    assert_eq!(store.reads.lock().unwrap().len(), 1);
}
