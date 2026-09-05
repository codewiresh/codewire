use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use codewire_access::{
    AccessError, AccessProfileName, AccessProfileReference, BrokerOperationId, BrokerRouteId,
    CapabilityPolicy, CapabilitySlot, CredentialAuthKind, CredentialStatus, GrantPermission,
    ProviderDefinition,
};
use codewire_protected_store::{ProtectedEntryId, ProtectedStoreError, ProtectedStorePersistence};
use tempfile::TempDir;

use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Fault {
    #[default]
    None,
    BeforeEffect,
    AfterEffect,
}

#[derive(Default)]
struct StoreState {
    entries: BTreeMap<String, Vec<u8>>,
    get_fault: Fault,
    put_fault: Fault,
    delete_fault: Fault,
    delete_calls: usize,
}

#[derive(Clone)]
pub(crate) struct TestProtectedStore {
    state: Arc<Mutex<StoreState>>,
    persistence: ProtectedStorePersistence,
}

impl TestProtectedStore {
    pub(crate) fn new(persistence: ProtectedStorePersistence) -> Self {
        Self {
            state: Arc::new(Mutex::new(StoreState::default())),
            persistence,
        }
    }

    fn empty_with_persistence(persistence: ProtectedStorePersistence) -> Self {
        Self::new(persistence)
    }

    fn set_put_fault(&self, fault: Fault) {
        self.state.lock().expect("store lock").put_fault = fault;
    }

    fn set_get_fault(&self, fault: Fault) {
        self.state.lock().expect("store lock").get_fault = fault;
    }

    fn set_delete_fault(&self, fault: Fault) {
        self.state.lock().expect("store lock").delete_fault = fault;
    }

    fn clear_faults(&self) {
        let mut state = self.state.lock().expect("store lock");
        state.get_fault = Fault::None;
        state.put_fault = Fault::None;
        state.delete_fault = Fault::None;
    }

    fn entry_count(&self) -> usize {
        self.state.lock().expect("store lock").entries.len()
    }

    fn entry_values(&self) -> Vec<Vec<u8>> {
        self.state
            .lock()
            .expect("store lock")
            .entries
            .values()
            .cloned()
            .collect()
    }

    fn delete_call_count(&self) -> usize {
        self.state.lock().expect("store lock").delete_calls
    }

    fn clear_entries(&self) {
        self.state.lock().expect("store lock").entries.clear();
    }
}

impl ProtectedStore for TestProtectedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        self.persistence
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        if state.get_fault != Fault::None {
            return Err(ProtectedStoreError::Unavailable);
        }
        state
            .entries
            .get(id.expose_reference())
            .map(|value| ProtectedValue::from_slice(value))
            .transpose()
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        if state.put_fault == Fault::BeforeEffect {
            return Err(ProtectedStoreError::Unavailable);
        }
        state.entries.insert(
            id.expose_reference().to_string(),
            value.expose_secret().to_vec(),
        );
        if state.put_fault == Fault::AfterEffect {
            return Err(ProtectedStoreError::Unavailable);
        }
        Ok(())
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtectedStoreError::Unavailable)?;
        state.delete_calls += 1;
        if state.delete_fault == Fault::BeforeEffect {
            return Err(ProtectedStoreError::Unavailable);
        }
        state.entries.remove(id.expose_reference());
        if state.delete_fault == Fault::AfterEffect {
            return Err(ProtectedStoreError::Unavailable);
        }
        Ok(())
    }
}

fn provider(value: &str) -> ProviderId {
    ProviderId::parse(value).expect("provider ID")
}

fn environment(value: &str) -> EnvironmentId {
    EnvironmentId::parse(value).expect("environment ID")
}

fn catalog() -> ProviderCatalog {
    ProviderCatalog::from_definitions([ProviderDefinition {
        id: provider("openai"),
        authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
        capabilities: [(
            CapabilitySlot::codex(),
            CapabilityPolicy {
                authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                permissions: BTreeSet::from([GrantPermission {
                    operation: BrokerOperationId::parse("responses").expect("operation ID"),
                    route: BrokerRouteId::parse("openai-api").expect("route ID"),
                }]),
            },
        )]
        .into_iter()
        .collect(),
    }])
    .expect("provider catalog")
}

fn workload_secret_rows(
    authority: &LocalCredentialAuthority<TestProtectedStore>,
) -> Vec<(String, i64, String)> {
    let connection = authority.connection().expect("credential database");
    let mut statement = connection
        .prepare(
            "SELECT key, material_generation, material_state
             FROM workload_secrets ORDER BY key, id",
        )
        .expect("prepare workload-secret state query");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query workload-secret state")
        .collect::<Result<Vec<_>, _>>()
        .expect("read workload-secret state")
}

fn workload_secret_journal_count(authority: &LocalCredentialAuthority<TestProtectedStore>) -> i64 {
    authority
        .connection()
        .expect("credential database")
        .query_row("SELECT COUNT(*) FROM workload_secret_journal", [], |row| {
            row.get(0)
        })
        .expect("count workload-secret journals")
}

fn catalog_with_incompatible_api_key_slot() -> ProviderCatalog {
    ProviderCatalog::from_definitions([ProviderDefinition {
        id: provider("openai"),
        authentication_kinds: BTreeSet::from([
            CredentialAuthKind::OAuth,
            CredentialAuthKind::ApiKey,
        ]),
        capabilities: BTreeMap::from([
            (
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::OAuth]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("responses").expect("operation ID"),
                        route: BrokerRouteId::parse("openai-api").expect("route ID"),
                    }]),
                },
            ),
            (
                CapabilitySlot::github(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("github-api").expect("operation ID"),
                        route: BrokerRouteId::parse("github-api").expect("route ID"),
                    }]),
                },
            ),
        ]),
    }])
    .expect("provider catalog")
}

fn authority_root(temp: &TempDir) -> PathBuf {
    temp.path().join("authority")
}

fn new_credential(name: &str) -> NewCredential {
    NewCredential {
        provider: provider("openai"),
        authentication_kind: CredentialAuthKind::OAuth,
        display_name: name.to_string(),
        account_hint: Some(format!("{name}@example.test")),
        expires_at_unix: Some(4_102_444_800),
    }
}

fn material(value: &[u8]) -> ProtectedValue {
    ProtectedValue::from_slice(value).expect("synthetic protected value")
}

fn profile_entries(credential: &CredentialId) -> BTreeMap<CapabilitySlot, CredentialId> {
    BTreeMap::from([(CapabilitySlot::codex(), credential.clone())])
}

fn operation_lease_request(environment_id: &EnvironmentId) -> CredentialOperationLeaseRequest {
    CredentialOperationLeaseRequest {
        environment_id: environment_id.clone(),
        environment_generation: 7,
        capability_slot: CapabilitySlot::codex(),
        operation: BrokerOperationId::parse("responses").expect("operation ID"),
        route: BrokerRouteId::parse("openai-api").expect("route ID"),
    }
}

fn bind_credential(
    authority: &LocalCredentialAuthority<TestProtectedStore>,
    environment_id: &EnvironmentId,
    credential_id: &CredentialId,
) -> AccessProfileRecord {
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(credential_id),
        )
        .expect("create profile");
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        })
        .expect("bind environment access");
    profile
}

#[test]
fn multiple_credentials_are_selected_by_profiles_without_material_in_metadata() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let work_secret = b"synthetic-work-oauth-token";
    let personal_secret = b"synthetic-personal-oauth-token";

    let work = authority
        .add_credential(new_credential("work"), material(work_secret))
        .expect("add work credential");
    let personal = authority
        .add_credential(new_credential("personal"), material(personal_secret))
        .expect("add personal credential");
    let work_profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(&work.metadata.id),
        )
        .expect("create work profile");
    let personal_profile = authority
        .create_profile(
            AccessProfileName::parse("personal").expect("profile name"),
            profile_entries(&personal.metadata.id),
        )
        .expect("create personal profile");

    assert_eq!(
        authority
            .list_credentials()
            .expect("list credentials")
            .len(),
        2
    );
    assert_eq!(authority.list_profiles().expect("list profiles").len(), 2);
    assert_eq!(
        authority
            .resolve_profile(&"user/work".parse().expect("profile reference"))
            .expect("resolve work profile")
            .profile,
        work_profile.profile
    );
    assert_eq!(
        authority
            .resolve_profile(&"user/personal".parse().expect("profile reference"))
            .expect("resolve personal profile")
            .profile,
        personal_profile.profile
    );
    let lease = authority
        .credential_material_for_test(&work.metadata.id)
        .expect("load work credential material");
    assert_eq!(lease.expose_secret(), work_secret);
    assert!(!format!("{lease:?}").contains("synthetic-work-oauth-token"));

    let database = fs::read(root.join(DATABASE_FILE)).expect("read metadata database");
    for secret in [work_secret.as_slice(), personal_secret.as_slice()] {
        assert!(
            !database
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }
}

#[test]
fn broker_operation_lease_rederives_the_bound_grant_before_material_access() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(&authority_root(&temp), store, catalog())
        .expect("open authority");
    let secret = b"synthetic-operation-token";
    let credential = authority
        .add_credential(new_credential("work"), material(secret))
        .expect("add credential");
    let environment_id = environment("env-lease");
    let profile = bind_credential(&authority, &environment_id, &credential.metadata.id);

    let mut request = operation_lease_request(&environment_id);
    request.environment_generation = 41;
    let lease = authority
        .lease_environment_credential_operation(&request)
        .expect("lease exact operation");
    assert_eq!(lease.credential.metadata.id, credential.metadata.id);
    assert_eq!(lease.grant.environment_id, environment_id);
    assert_eq!(lease.grant.environment_generation, 41);
    assert_eq!(lease.grant.profile_id, profile.profile.id);
    assert_eq!(lease.grant.profile_revision, profile.profile.revision);
    assert_eq!(lease.grant.capability_slot, CapabilitySlot::codex());
    assert_eq!(lease.permission.operation.as_str(), "responses");
    assert_eq!(lease.permission.route.as_str(), "openai-api");
    let rendered = format!("{lease:?}");
    assert!(!rendered.contains("synthetic-operation-token"));
    assert!(!rendered.contains("protected_entry"));
    assert_eq!(lease.with_material(<[u8]>::to_vec), secret);
}

#[test]
fn repository_lease_binds_exact_github_profile_revision_and_route() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(
        &authority_root(&temp),
        store,
        codewire_access::builtin_provider_catalog(),
    )
    .expect("open authority");
    let credential = authority
        .add_credential(
            NewCredential {
                provider: provider("github"),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "github-work".to_owned(),
                account_hint: None,
                expires_at_unix: None,
            },
            material(b"synthetic-github-token"),
        )
        .expect("add GitHub credential");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("github-work").unwrap(),
            BTreeMap::from([(CapabilitySlot::github(), credential.metadata.id.clone())]),
        )
        .expect("create GitHub profile");
    let request = RepositoryCredentialLeaseRequest {
        request_id: Uuid::new_v4(),
        profile_id: profile.profile.id.clone(),
        profile_revision: profile.profile.revision,
        source: "https://github.com/codewire/codewire.git".to_owned(),
        branch: "main".to_owned(),
        revision: String::new(),
    };
    let admission = authority
        .admit_repository_credential_operation(&request)
        .expect("admit repository lease");
    assert_eq!(admission.credential.metadata.id, credential.metadata.id);
    assert_eq!(admission.profile_id, profile.profile.id);
    assert_eq!(admission.profile_revision, 1);
    assert_eq!(
        admission.permission,
        crate::repository::github_fetch_permission()
    );
    assert_eq!(admission.material_generation, 1);

    let mut invalid_source = request.clone();
    invalid_source.source = "https://example.com/codewire/codewire.git".to_owned();
    assert!(matches!(
        authority.admit_repository_credential_operation(&invalid_source),
        Err(LocalCredentialError::CredentialOperationLeaseDenied)
    ));
    let mut missing_revision = request.clone();
    missing_revision.profile_revision = 2;
    assert!(matches!(
        authority.admit_repository_credential_operation(&missing_revision),
        Err(LocalCredentialError::ProfileRevisionNotFound)
    ));
    authority
        .revoke_credential(&credential.metadata.id)
        .expect("revoke GitHub credential");
    assert!(matches!(
        authority.admit_repository_credential_operation(&request),
        Err(LocalCredentialError::CredentialInactive)
    ));
}

#[test]
fn broker_operation_lease_denies_unbound_capabilities_routes_and_operations() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
            .expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"synthetic-token"))
        .expect("add credential");
    let environment_id = environment("env-lease");
    bind_credential(&authority, &environment_id, &credential.metadata.id);
    store.set_get_fault(Fault::BeforeEffect);

    let mut request = operation_lease_request(&environment_id);
    request.capability_slot = CapabilitySlot::github();
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::CredentialOperationLeaseDenied)
    ));

    let mut request = operation_lease_request(&environment_id);
    request.route = BrokerRouteId::parse("other-route").expect("route ID");
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::CredentialOperationLeaseDenied)
    ));

    let mut request = operation_lease_request(&environment_id);
    request.operation = BrokerOperationId::parse("other-operation").expect("operation ID");
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::CredentialOperationLeaseDenied)
    ));

    let request = operation_lease_request(&environment("unbound-environment"));
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::EnvironmentBindingNotFound)
    ));

    let mut request = operation_lease_request(&environment_id);
    request.environment_generation = 0;
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::Access(AccessError::ZeroGeneration {
            field: "environment generation"
        }))
    ));
}

#[test]
fn broker_operation_lease_denies_expired_material_before_store_access() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
            .expect("open authority");
    let credential = authority
        .add_credential(new_credential("expired"), material(b"expired-token"))
        .expect("add credential");
    let environment_id = environment("env-expired");
    bind_credential(&authority, &environment_id, &credential.metadata.id);
    authority
        .connection()
        .expect("database connection")
        .execute(
            "UPDATE credentials SET expires_at_unix = 1 WHERE id = ?1",
            [credential.metadata.id.as_str()],
        )
        .expect("expire credential after binding");
    store.set_get_fault(Fault::BeforeEffect);

    assert!(matches!(
        authority.lease_environment_credential_operation(&operation_lease_request(&environment_id)),
        Err(LocalCredentialError::Access(
            AccessError::CredentialExpired { .. }
        ))
    ));
}

#[test]
fn broker_operation_lease_tracks_rotation_and_fails_closed_on_revocation_or_storage_loss() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
            .expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"first-token"))
        .expect("add credential");
    let environment_id = environment("env-lease");
    bind_credential(&authority, &environment_id, &credential.metadata.id);
    let request = operation_lease_request(&environment_id);

    let first = authority
        .lease_environment_credential_operation(&request)
        .expect("lease first generation");
    assert_eq!(first.grant.credential_revocation_generation, 1);
    assert_eq!(first.with_material(<[u8]>::to_vec), b"first-token");

    authority
        .rotate_credential_material(&credential.metadata.id, material(b"second-token"), None)
        .expect("rotate credential");
    let rotated = authority
        .lease_environment_credential_operation(&request)
        .expect("lease rotated generation");
    assert_eq!(rotated.grant.credential_revocation_generation, 2);
    assert_eq!(rotated.with_material(<[u8]>::to_vec), b"second-token");

    store.set_get_fault(Fault::BeforeEffect);
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::Unavailable
        ))
    ));
    store.clear_faults();
    store.clear_entries();
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::CredentialMaterialMissing)
    ));

    authority
        .revoke_credential(&credential.metadata.id)
        .expect("revoke credential");
    assert!(matches!(
        authority.lease_environment_credential_operation(&request),
        Err(LocalCredentialError::Access(
            AccessError::CredentialInactive { .. }
        ))
    ));
}

#[test]
fn oauth_refresh_serializes_and_promotes_one_exact_protected_generation() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
            .expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"first-oauth-bundle"))
        .expect("add credential");
    let environment_id = environment("env-refresh");
    bind_credential(&authority, &environment_id, &credential.metadata.id);
    let request = operation_lease_request(&environment_id);
    let lease = authority
        .lease_environment_credential_operation(&request)
        .expect("lease first generation");
    let material_generation = lease.material_generation();
    let revocation_generation = lease.credential.metadata.revocation_generation;
    let channel_id = Uuid::new_v4();
    let refresh_id = Uuid::new_v4();
    let permit = authority
        .begin_environment_credential_refresh(
            channel_id,
            refresh_id,
            &request,
            &credential.metadata.id,
            revocation_generation,
            material_generation,
        )
        .expect("begin refresh");
    assert_eq!(permit.current_material_generation, 1);
    assert_eq!(permit.next_material_generation, 2);
    assert_eq!(
        authority.begin_environment_credential_refresh(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &request,
            &credential.metadata.id,
            revocation_generation,
            material_generation,
        ),
        Err(LocalCredentialError::CredentialRefreshInProgress)
    );
    assert_eq!(
        authority.rotate_credential_material(
            &credential.metadata.id,
            material(b"manual-rotation"),
            None,
        ),
        Err(LocalCredentialError::CredentialRefreshInProgress)
    );
    assert_eq!(
        authority.delete_credential(&credential.metadata.id),
        Err(LocalCredentialError::CredentialRefreshInProgress)
    );

    let next_entry = protected_entry_id(&credential.metadata.id, 2).expect("next entry");
    store
        .put(&next_entry, &material(b"refreshed-oauth-bundle"))
        .expect("write refreshed bundle");
    let (refreshed, committed_material_generation) = authority
        .commit_environment_credential_refresh(channel_id, refresh_id)
        .expect("commit refresh");
    assert_eq!(refreshed.metadata.revocation_generation, 2);
    assert_eq!(committed_material_generation, 2);
    let lease = authority
        .lease_environment_credential_operation(&request)
        .expect("lease refreshed generation");
    assert_eq!(lease.material_generation(), 2);
    assert_eq!(
        lease.with_material(<[u8]>::to_vec),
        b"refreshed-oauth-bundle"
    );
    assert_eq!(store.entry_count(), 1);
}

#[test]
fn oauth_refresh_recovers_a_rotated_provider_token_after_authority_crash() {
    for persistence in [
        ProtectedStorePersistence::OperatingSystem,
        ProtectedStorePersistence::ProcessLifetime,
    ] {
        let temp = TempDir::new().expect("temporary directory");
        let root = authority_root(&temp);
        let store = TestProtectedStore::new(persistence);
        let credential_id;
        let environment_id = environment("env-refresh-recovery");
        {
            let authority = LocalCredentialAuthority::open(&root, store.clone(), catalog())
                .expect("open authority");
            let credential = authority
                .add_credential(new_credential("work"), material(b"first-oauth-bundle"))
                .expect("add credential");
            credential_id = credential.metadata.id.clone();
            bind_credential(&authority, &environment_id, &credential_id);
            authority
                .begin_environment_credential_refresh(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    &operation_lease_request(&environment_id),
                    &credential_id,
                    1,
                    1,
                )
                .expect("begin refresh");
            store
                .put(
                    &protected_entry_id(&credential_id, 2).expect("next entry"),
                    &material(b"durable-refreshed-bundle"),
                )
                .expect("write next bundle");
            // Dropping the authority models a crash after the provider rotated
            // its refresh token and the broker durably wrote the new bundle,
            // but before the metadata-only commit reply.
        }

        let authority = LocalCredentialAuthority::open(&root, store.clone(), catalog())
            .expect("recover authority");
        let lease = authority
            .lease_environment_credential_operation(&operation_lease_request(&environment_id))
            .expect("lease recovered refresh");
        assert_eq!(lease.material_generation(), 2);
        assert_eq!(lease.credential.metadata.revocation_generation, 2);
        assert_eq!(lease.credential.metadata.status, CredentialStatus::Active);
        assert_eq!(
            lease.with_material(<[u8]>::to_vec),
            b"durable-refreshed-bundle"
        );
        assert_eq!(store.entry_count(), 1);
    }
}

#[test]
fn orphaned_oauth_refresh_marker_fails_authority_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    drop(authority);
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open metadata database");
    connection
        .execute(
            "INSERT INTO authority_metadata(key, value)
             VALUES ('credential_refresh/orphaned', '2')",
            [],
        )
        .expect("insert orphaned refresh marker");
    drop(connection);

    assert!(matches!(
        LocalCredentialAuthority::open(&root, store, catalog()),
        Err(LocalCredentialError::CorruptMetadata)
    ));
}

#[test]
fn unsupported_authentication_kind_is_rejected_before_protected_store_access() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
            .expect("open authority");
    let mut input = new_credential("unsupported-api-key");
    input.authentication_kind = CredentialAuthKind::ApiKey;

    assert_eq!(
        authority.add_credential(input, material(b"synthetic-api-key")),
        Err(LocalCredentialError::Access(
            AccessError::UnsupportedAuthenticationKind {
                provider: provider("openai"),
                kind: CredentialAuthKind::ApiKey,
            }
        ))
    );
    assert_eq!(store.entry_count(), 0);
    assert!(
        authority
            .list_credentials()
            .expect("list credentials")
            .is_empty()
    );
}

#[test]
fn names_are_unique_case_insensitively_and_metadata_lifecycle_is_explicit() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(&authority_root(&temp), store, catalog())
        .expect("open authority");
    let credential = authority
        .add_credential(new_credential("Work"), material(b"synthetic-token"))
        .expect("add credential");
    assert_eq!(
        authority.add_credential(new_credential("work"), material(b"other-token")),
        Err(LocalCredentialError::AlreadyExists)
    );
    assert_eq!(
        authority
            .resolve_credential("wOrK")
            .expect("resolve credential")
            .metadata
            .id,
        credential.metadata.id
    );

    let renamed = authority
        .rename_credential(&credential.metadata.id, "personal".to_string())
        .expect("rename credential");
    assert_eq!(renamed.metadata.display_name, "personal");
    let revoked = authority
        .revoke_credential(&credential.metadata.id)
        .expect("revoke credential");
    assert_eq!(revoked.metadata.status, CredentialStatus::Revoked);
    assert_eq!(revoked.metadata.revocation_generation, 2);
    assert!(matches!(
        authority.credential_material_for_test(&credential.metadata.id),
        Err(LocalCredentialError::CredentialInactive)
    ));
}

#[test]
fn profile_revisions_are_immutable_and_only_current_references_block_deletion() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(&authority_root(&temp), store, catalog())
        .expect("open authority");
    let first = authority
        .add_credential(new_credential("first"), material(b"first-token"))
        .expect("add first credential");
    let second = authority
        .add_credential(new_credential("second"), material(b"second-token"))
        .expect("add second credential");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(&first.metadata.id),
        )
        .expect("create profile");
    assert_eq!(
        authority.delete_credential(&first.metadata.id),
        Err(LocalCredentialError::CredentialInUse)
    );

    let revision_two = authority
        .update_profile(&profile.profile.id, 1, profile_entries(&second.metadata.id))
        .expect("update profile");
    assert_eq!(revision_two.profile.revision, 2);
    let revisions = authority
        .list_profile_revisions(&profile.profile.id)
        .expect("list immutable revisions");
    assert_eq!(revisions.len(), 2);
    assert_eq!(
        revisions[0].profile.entries[&CapabilitySlot::codex()],
        first.metadata.id
    );
    assert_eq!(
        revisions[1].profile.entries[&CapabilitySlot::codex()],
        second.metadata.id
    );
    assert_eq!(
        authority
            .get_profile_revision(&profile.profile.id, 1)
            .expect("load first revision")
            .profile,
        revisions[0].profile
    );
    assert_eq!(
        authority.get_profile_revision(&profile.profile.id, 3),
        Err(LocalCredentialError::ProfileRevisionNotFound)
    );
    assert_eq!(
        authority.update_profile(&profile.profile.id, 1, profile_entries(&first.metadata.id)),
        Err(LocalCredentialError::StaleProfileRevision)
    );
    authority
        .delete_credential(&first.metadata.id)
        .expect("historical reference does not block deletion");
    assert_eq!(
        authority
            .get_profile_revision(&profile.profile.id, 1)
            .expect("historical revision survives credential deletion")
            .profile
            .entries[&CapabilitySlot::codex()],
        first.metadata.id
    );
    assert_eq!(
        authority.delete_credential(&second.metadata.id),
        Err(LocalCredentialError::CredentialInUse)
    );
    authority
        .delete_profile(&profile.profile.id)
        .expect("delete profile");
    authority
        .delete_credential(&second.metadata.id)
        .expect("delete unreferenced credential");
}

#[test]
fn environment_bindings_pin_revisions_survive_restart_and_guard_deletion() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let first = authority
        .add_credential(new_credential("first"), material(b"first-token"))
        .expect("add first credential");
    let second = authority
        .add_credential(new_credential("second"), material(b"second-token"))
        .expect("add second credential");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(&first.metadata.id),
        )
        .expect("create profile");
    let environment_id = environment("env-one");
    let binding = EnvironmentAccessBinding {
        environment_id: environment_id.clone(),
        profile_id: profile.profile.id.clone(),
        profile_revision: profile.profile.revision,
    };
    let created = authority
        .create_environment_access_binding(binding.clone())
        .expect("create binding");
    assert_eq!(created.binding, binding);
    assert_eq!(
        authority.create_environment_access_binding(binding.clone()),
        Err(LocalCredentialError::EnvironmentBindingAlreadyExists)
    );

    let updated_profile = authority
        .update_profile(
            &profile.profile.id,
            profile.profile.revision,
            profile_entries(&second.metadata.id),
        )
        .expect("update profile");
    let grants = authority
        .evaluate_environment_grants(&environment_id, 7)
        .expect("evaluate pinned grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].environment_generation, 7);
    assert_eq!(grants[0].profile_revision, profile.profile.revision);
    assert_eq!(grants[0].credential_id, first.metadata.id);
    assert_eq!(
        authority.delete_credential(&first.metadata.id),
        Err(LocalCredentialError::CredentialInUse)
    );
    assert_eq!(
        authority.delete_profile(&profile.profile.id),
        Err(LocalCredentialError::ProfileInUse)
    );
    drop(authority);

    let authority =
        LocalCredentialAuthority::open(&root, store, catalog()).expect("reopen authority");
    assert_eq!(
        authority
            .list_environment_access_bindings()
            .expect("list bindings"),
        vec![created.clone()]
    );
    assert_eq!(
        authority.replace_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            updated_profile.profile.revision,
            profile.profile.id.clone(),
            updated_profile.profile.revision,
        ),
        Err(LocalCredentialError::StaleEnvironmentBinding)
    );
    let replaced = authority
        .replace_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            profile.profile.revision,
            profile.profile.id.clone(),
            updated_profile.profile.revision,
        )
        .expect("replace binding");
    assert_eq!(
        replaced.binding.profile_revision,
        updated_profile.profile.revision
    );
    assert_eq!(replaced.created_at_unix_ms, created.created_at_unix_ms);
    assert!(replaced.updated_at_unix_ms >= created.updated_at_unix_ms);
    let grants = authority
        .evaluate_environment_grants(&environment_id, 8)
        .expect("evaluate replaced grants");
    assert_eq!(grants[0].environment_generation, 8);
    assert_eq!(grants[0].credential_id, second.metadata.id);
    authority
        .delete_credential(&first.metadata.id)
        .expect("delete unbound historical credential");
    assert!(matches!(
        authority.replace_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            updated_profile.profile.revision,
            profile.profile.id.clone(),
            profile.profile.revision,
        ),
        Err(LocalCredentialError::Access(
            AccessError::CredentialMissing { .. }
        ))
    ));
    assert_eq!(
        authority
            .get_environment_access_binding(&environment_id)
            .expect("binding remains current")
            .binding
            .profile_revision,
        updated_profile.profile.revision
    );

    authority
        .revoke_credential(&second.metadata.id)
        .expect("revoke selected credential");
    assert!(matches!(
        authority.evaluate_environment_grants(&environment_id, 9),
        Err(LocalCredentialError::Access(
            AccessError::CredentialInactive { .. }
        ))
    ));
    assert_eq!(
        authority.delete_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            profile.profile.revision,
        ),
        Err(LocalCredentialError::StaleEnvironmentBinding)
    );
    authority
        .delete_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            updated_profile.profile.revision,
        )
        .expect("delete binding");
    authority
        .delete_profile(&profile.profile.id)
        .expect("delete unbound profile");
    assert_eq!(
        authority.get_environment_access_binding(&environment_id),
        Err(LocalCredentialError::EnvironmentBindingNotFound)
    );
}

#[test]
fn environment_binding_rejects_missing_revisions_and_zero_generations() {
    let temp = TempDir::new().expect("temporary directory");
    let authority = LocalCredentialAuthority::open(
        &authority_root(&temp),
        TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
        catalog(),
    )
    .expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"synthetic-token"))
        .expect("add credential");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(&credential.metadata.id),
        )
        .expect("create profile");
    let environment_id = environment("env-one");

    assert_eq!(
        authority.create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: 99,
        }),
        Err(LocalCredentialError::ProfileRevisionNotFound)
    );
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
        })
        .expect("create binding");
    assert!(matches!(
        authority.evaluate_environment_grants(&environment_id, 0),
        Err(LocalCredentialError::Access(AccessError::ZeroGeneration {
            field: "environment generation"
        }))
    ));
}

#[test]
fn corrupt_environment_binding_metadata_fails_authority_restart() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"synthetic-token"))
        .expect("add credential");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(&credential.metadata.id),
        )
        .expect("create profile");
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment("env-one"),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
        })
        .expect("create binding");
    drop(authority);

    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open metadata database");
    connection
        .execute(
            "UPDATE environment_access_bindings SET environment_id = 'INVALID'",
            [],
        )
        .expect("tamper binding");
    drop(connection);
    assert!(matches!(
        LocalCredentialAuthority::open(&root, store, catalog()),
        Err(LocalCredentialError::CorruptMetadata)
    ));
}

#[test]
fn rotation_switches_generations_without_overwriting_the_active_entry() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"old-synthetic-token"))
        .expect("add credential");
    let rotated = authority
        .rotate_credential_material(
            &credential.metadata.id,
            material(b"new-synthetic-token"),
            Some(4_102_444_801),
        )
        .expect("rotate credential");

    assert_eq!(rotated.metadata.id, credential.metadata.id);
    assert_eq!(rotated.metadata.revocation_generation, 2);
    assert_eq!(rotated.metadata.expires_at_unix, Some(4_102_444_801));
    assert!(!rotated.protected_store_cleanup_pending);
    assert_eq!(store.entry_count(), 1);
    assert_eq!(
        authority
            .credential_material_for_test(&credential.metadata.id)
            .expect("rotated material")
            .expose_secret(),
        b"new-synthetic-token"
    );
    let database = fs::read(root.join(DATABASE_FILE)).expect("read metadata database");
    assert!(
        !database
            .windows(b"new-synthetic-token".len())
            .any(|window| window == b"new-synthetic-token")
    );
}

#[test]
fn interrupted_rotation_rolls_back_the_uncommitted_generation() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"active-token"))
        .expect("add credential");
    store.set_put_fault(Fault::AfterEffect);
    store.set_delete_fault(Fault::BeforeEffect);
    assert_eq!(
        authority.rotate_credential_material(
            &credential.metadata.id,
            material(b"uncommitted-token"),
            None
        ),
        Err(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::Unavailable
        ))
    );
    assert_eq!(store.entry_count(), 2);
    assert!(
        authority
            .get_credential(&credential.metadata.id)
            .expect("credential metadata")
            .protected_store_cleanup_pending
    );
    assert_eq!(
        authority
            .credential_material_for_test(&credential.metadata.id)
            .expect("original material")
            .expose_secret(),
        b"active-token"
    );
    drop(authority);

    store.clear_faults();
    let recovered =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("recover authority");
    assert_eq!(store.entry_count(), 1);
    assert!(
        !recovered
            .get_credential(&credential.metadata.id)
            .expect("credential metadata")
            .protected_store_cleanup_pending
    );
    assert_eq!(
        recovered
            .credential_material_for_test(&credential.metadata.id)
            .expect("recovered material")
            .expose_secret(),
        b"active-token"
    );
}

#[test]
fn committed_rotation_stays_usable_while_retired_entry_cleanup_is_pending() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"retired-token"))
        .expect("add credential");
    store.set_delete_fault(Fault::BeforeEffect);
    let rotated = authority
        .rotate_credential_material(
            &credential.metadata.id,
            material(b"active-rotated-token"),
            None,
        )
        .expect("committed rotation");
    assert!(rotated.protected_store_cleanup_pending);
    assert_eq!(rotated.metadata.revocation_generation, 2);
    assert_eq!(store.entry_count(), 2);
    assert_eq!(
        authority
            .credential_material_for_test(&credential.metadata.id)
            .expect("new active material")
            .expose_secret(),
        b"active-rotated-token"
    );
    drop(authority);

    store.clear_faults();
    let recovered =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("recover authority");
    assert_eq!(store.entry_count(), 1);
    assert!(
        !recovered
            .get_credential(&credential.metadata.id)
            .expect("credential metadata")
            .protected_store_cleanup_pending
    );
}

#[test]
fn deleting_a_credential_removes_active_and_retired_entries_exactly() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"retired-token"))
        .expect("add credential");
    store.set_delete_fault(Fault::BeforeEffect);
    authority
        .rotate_credential_material(&credential.metadata.id, material(b"active-token"), None)
        .expect("commit rotation with pending cleanup");
    assert_eq!(store.entry_count(), 2);

    store.clear_faults();
    authority
        .delete_credential(&credential.metadata.id)
        .expect("delete both generations");
    assert_eq!(store.entry_count(), 0);
    assert!(
        authority
            .list_credentials()
            .expect("list credentials")
            .is_empty()
    );
}

#[test]
fn recovery_never_deletes_a_journal_entry_outside_the_credential_generation() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"retired-token"))
        .expect("add credential");
    store.set_delete_fault(Fault::BeforeEffect);
    authority
        .rotate_credential_material(&credential.metadata.id, material(b"active-token"), None)
        .expect("commit rotation with pending cleanup");
    drop(authority);
    store.clear_faults();

    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open metadata database");
    connection
        .execute(
            "UPDATE protected_entry_journal
             SET protected_entry_id = 'local/credentials/other/material-v1'",
            [],
        )
        .expect("tamper journal entry");
    drop(connection);
    let calls_before = store.delete_call_count();
    assert!(matches!(
        LocalCredentialAuthority::open(&root, store.clone(), catalog()),
        Err(LocalCredentialError::CorruptMetadata)
    ));
    assert_eq!(store.delete_call_count(), calls_before);
    assert_eq!(store.entry_count(), 2);
}

#[test]
fn local_profiles_reject_organization_scope_and_incompatible_credentials() {
    let temp = TempDir::new().expect("temporary directory");
    let authority = LocalCredentialAuthority::open(
        &authority_root(&temp),
        TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
        catalog_with_incompatible_api_key_slot(),
    )
    .expect("open authority");
    let reference: AccessProfileReference = "organization/work".parse().expect("profile reference");
    assert_eq!(
        authority.resolve_profile(&reference),
        Err(LocalCredentialError::Access(
            AccessError::LocalOrganizationUnsupported
        ))
    );

    let credential = authority
        .add_credential(
            NewCredential {
                authentication_kind: CredentialAuthKind::ApiKey,
                ..new_credential("api-key")
            },
            material(b"synthetic-api-key"),
        )
        .expect("persist credential metadata before profile validation");
    assert!(matches!(
        authority.create_profile(
            AccessProfileName::parse("invalid").expect("profile name"),
            profile_entries(&credential.metadata.id)
        ),
        Err(LocalCredentialError::Access(
            AccessError::UnsupportedCapability { .. }
        ))
    ));
}

#[test]
fn recovery_rolls_back_an_interrupted_protected_write() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    store.set_put_fault(Fault::AfterEffect);
    store.set_delete_fault(Fault::BeforeEffect);
    assert_eq!(
        authority.add_credential(new_credential("work"), material(b"interrupted-token")),
        Err(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::Unavailable
        ))
    );
    assert_eq!(store.entry_count(), 1);
    drop(authority);

    store.clear_faults();
    let recovered =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("recover authority");
    assert!(
        recovered
            .list_credentials()
            .expect("list credentials")
            .is_empty()
    );
    assert_eq!(store.entry_count(), 0);
}

#[test]
fn recovery_completes_an_interrupted_protected_delete() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"deletion-token"))
        .expect("add credential");
    store.set_delete_fault(Fault::AfterEffect);
    assert_eq!(
        authority.delete_credential(&credential.metadata.id),
        Err(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::Unavailable
        ))
    );
    assert_eq!(store.entry_count(), 0);
    drop(authority);

    store.clear_faults();
    let recovered =
        LocalCredentialAuthority::open(&root, store, catalog()).expect("recover authority");
    assert!(
        recovered
            .list_credentials()
            .expect("list credentials")
            .is_empty()
    );
}

#[test]
fn unavailable_protected_store_fails_recovery_without_discarding_the_journal() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    store.set_put_fault(Fault::AfterEffect);
    store.set_delete_fault(Fault::BeforeEffect);
    let _ = authority.add_credential(new_credential("work"), material(b"journal-token"));
    drop(authority);

    assert!(matches!(
        LocalCredentialAuthority::open(&root, store.clone(), catalog()),
        Err(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::Unavailable
        ))
    ));
    assert_eq!(store.entry_count(), 1);
    store.clear_faults();
    let recovered = LocalCredentialAuthority::open(&root, store.clone(), catalog())
        .expect("recover retained journal");
    assert!(
        recovered
            .list_credentials()
            .expect("list credentials")
            .is_empty()
    );
    assert_eq!(store.entry_count(), 0);
}

#[test]
fn process_lifetime_material_loss_marks_persisted_metadata_expired() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let original = TestProtectedStore::new(ProtectedStorePersistence::ProcessLifetime);
    let authority =
        LocalCredentialAuthority::open(&root, original, catalog()).expect("open authority");
    let credential = authority
        .add_credential(new_credential("work"), material(b"ephemeral-token"))
        .expect("add credential");
    drop(authority);

    let empty =
        TestProtectedStore::empty_with_persistence(ProtectedStorePersistence::ProcessLifetime);
    let reopened =
        LocalCredentialAuthority::open(&root, empty, catalog()).expect("reopen authority");
    assert_eq!(
        reopened
            .get_credential(&credential.metadata.id)
            .expect("credential metadata")
            .metadata
            .status,
        CredentialStatus::Expired
    );
    assert!(matches!(
        reopened.credential_material_for_test(&credential.metadata.id),
        Err(LocalCredentialError::CredentialInactive)
    ));
}

#[test]
fn protected_store_identity_is_persisted_and_must_match() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let authority = LocalCredentialAuthority::open(
        &root,
        TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
        catalog(),
    )
    .expect("open authority");
    drop(authority);

    assert!(matches!(
        LocalCredentialAuthority::open(
            &root,
            TestProtectedStore::new(ProtectedStorePersistence::ProcessLifetime),
            catalog()
        ),
        Err(LocalCredentialError::ProtectedStoreMismatch)
    ));
}

#[test]
fn one_authority_process_owns_the_metadata_and_protected_store_journal() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    assert!(matches!(
        LocalCredentialAuthority::open(&root, store.clone(), catalog()),
        Err(LocalCredentialError::AlreadyRunning)
    ));
    drop(authority);
    LocalCredentialAuthority::open(&root, store, catalog()).expect("reacquire authority lock");
}

#[cfg(unix)]
#[test]
fn authority_rejects_non_private_roots_and_database_symlinks() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let temp = TempDir::new().expect("temporary directory");
    let public_root = temp.path().join("public");
    fs::create_dir(&public_root).expect("create public root");
    fs::set_permissions(&public_root, fs::Permissions::from_mode(0o755))
        .expect("set public permissions");
    assert!(matches!(
        LocalCredentialAuthority::open(
            &public_root,
            TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
            catalog()
        ),
        Err(LocalCredentialError::InvalidDatabasePath)
    ));

    let symlink_root = temp.path().join("symlink-root");
    fs::create_dir(&symlink_root).expect("create symlink root");
    fs::set_permissions(&symlink_root, fs::Permissions::from_mode(0o700))
        .expect("set private permissions");
    let target = temp.path().join("database-target");
    fs::write(&target, []).expect("create target");
    symlink(&target, symlink_root.join(DATABASE_FILE)).expect("create database symlink");
    assert!(matches!(
        LocalCredentialAuthority::open(
            &symlink_root,
            TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
            catalog()
        ),
        Err(LocalCredentialError::InvalidDatabasePath)
    ));

    let real_parent = temp.path().join("real-parent");
    fs::create_dir(&real_parent).expect("create real parent");
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))
        .expect("set real parent permissions");
    let linked_parent = temp.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).expect("create parent symlink");
    assert!(matches!(
        LocalCredentialAuthority::open(
            &linked_parent.join("authority"),
            TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
            catalog()
        ),
        Err(LocalCredentialError::InvalidDatabasePath)
    ));

    let writable_parent = temp.path().join("writable-parent");
    fs::create_dir(&writable_parent).expect("create writable parent");
    fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))
        .expect("set writable parent permissions");
    let private_child = writable_parent.join("authority");
    fs::create_dir(&private_child).expect("create private child");
    fs::set_permissions(&private_child, fs::Permissions::from_mode(0o700))
        .expect("set private child permissions");
    assert!(matches!(
        LocalCredentialAuthority::open(
            &private_child,
            TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
            catalog()
        ),
        Err(LocalCredentialError::InvalidDatabasePath)
    ));
}

#[test]
fn unsupported_database_schema_fails_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let authority = LocalCredentialAuthority::open(
        &root,
        TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
        catalog(),
    )
    .expect("open authority");
    drop(authority);
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open metadata database");
    connection
        .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION + 1)
        .expect("change schema version");
    drop(connection);

    assert!(matches!(
        LocalCredentialAuthority::open(
            &root,
            TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem),
            catalog()
        ),
        Err(LocalCredentialError::UnsupportedSchema)
    ));
}

#[test]
fn schema_v1_is_rejected_without_mutation() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&root, store.clone(), catalog()).expect("open authority");
    authority
        .add_credential(new_credential("existing"), material(b"synthetic-existing"))
        .expect("add credential");
    drop(authority);

    let database = root.join(DATABASE_FILE);
    let connection = Connection::open(&database).expect("open metadata database");
    connection
        .execute_batch(
            "DROP TABLE workload_secret_journal;
             DROP INDEX workload_secrets_scope;
             DROP TABLE workload_secrets;
             DROP TABLE secret_projects;
             PRAGMA user_version = 1;",
        )
        .expect("construct schema v1 fixture");
    let journal: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .expect("set schema v1 journal mode");
    assert!(journal.eq_ignore_ascii_case("wal"));
    drop(connection);

    assert!(matches!(
        LocalCredentialAuthority::open(&root, store.clone(), catalog()),
        Err(LocalCredentialError::UnsupportedSchema)
    ));
    let connection = Connection::open(&database).expect("reopen metadata database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read rejected schema version");
    assert_eq!(version, 1);
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("read rejected schema journal mode");
    assert!(journal.eq_ignore_ascii_case("wal"));
    for object in [
        "secret_projects",
        "workload_secrets",
        "workload_secrets_scope",
        "workload_secret_journal",
    ] {
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [object],
                |row| row.get(0),
            )
            .expect("inspect rejected schema");
        assert_eq!(present, 0, "{object}");
    }
    let credential_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE display_name = 'existing'",
            [],
            |row| row.get(0),
        )
        .expect("inspect preserved credential metadata");
    assert_eq!(credential_count, 1);
    assert_eq!(store.entry_count(), 1);
}

#[test]
fn workload_secret_initial_write_recovers_in_live_authority_for_both_fault_timings() {
    for fault in [Fault::BeforeEffect, Fault::AfterEffect] {
        let temp = TempDir::new().expect("temporary directory");
        let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
        let authority =
            LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
                .unwrap();

        store.set_put_fault(fault);
        assert!(
            authority
                .set_user_workload_secret("PENDING", material(b"synthetic-pending"))
                .is_err()
        );
        assert_eq!(
            workload_secret_rows(&authority),
            vec![("PENDING".into(), 1, "pending_write".into())]
        );
        assert_eq!(workload_secret_journal_count(&authority), 1);
        let expected_values = match fault {
            Fault::BeforeEffect => Vec::new(),
            Fault::AfterEffect => vec![b"synthetic-pending".to_vec()],
            Fault::None => unreachable!(),
        };
        assert_eq!(store.entry_values(), expected_values);

        store.clear_faults();
        assert!(authority.list_user_workload_secrets().unwrap().is_empty());
        assert!(workload_secret_rows(&authority).is_empty());
        assert_eq!(workload_secret_journal_count(&authority), 0);
        assert!(store.entry_values().is_empty());
    }
}

#[test]
fn workload_secret_rotation_write_recovers_in_live_authority_for_both_fault_timings() {
    for fault in [Fault::BeforeEffect, Fault::AfterEffect] {
        let temp = TempDir::new().expect("temporary directory");
        let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
        let authority =
            LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
                .unwrap();
        authority
            .set_user_workload_secret("ROTATED", material(b"synthetic-old"))
            .unwrap();

        store.set_put_fault(fault);
        assert!(
            authority
                .set_user_workload_secret("ROTATED", material(b"synthetic-uncommitted"))
                .is_err()
        );
        assert_eq!(
            workload_secret_rows(&authority),
            vec![("ROTATED".into(), 1, "ready".into())]
        );
        assert_eq!(workload_secret_journal_count(&authority), 1);
        let expected_values = match fault {
            Fault::BeforeEffect => vec![b"synthetic-old".to_vec()],
            Fault::AfterEffect => {
                vec![b"synthetic-old".to_vec(), b"synthetic-uncommitted".to_vec()]
            }
            Fault::None => unreachable!(),
        };
        assert_eq!(store.entry_values(), expected_values);

        store.clear_faults();
        let recovered = authority.list_user_workload_secrets().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(!recovered[0].protected_store_cleanup_pending);
        assert_eq!(
            workload_secret_rows(&authority),
            vec![("ROTATED".into(), 1, "ready".into())]
        );
        assert_eq!(workload_secret_journal_count(&authority), 0);
        assert_eq!(store.entry_values(), vec![b"synthetic-old".to_vec()]);
    }
}

#[test]
fn committed_workload_secret_rotation_reports_cleanup_pending_for_both_fault_timings() {
    for fault in [Fault::BeforeEffect, Fault::AfterEffect] {
        let temp = TempDir::new().expect("temporary directory");
        let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
        let authority =
            LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
                .unwrap();
        authority
            .set_user_workload_secret("ROTATED", material(b"synthetic-old"))
            .unwrap();

        store.set_delete_fault(fault);
        let rotated = authority
            .set_user_workload_secret("ROTATED", material(b"synthetic-new"))
            .expect("committed rotation remains successful");
        assert!(rotated.protected_store_cleanup_pending);
        assert_eq!(
            workload_secret_rows(&authority),
            vec![("ROTATED".into(), 2, "ready".into())]
        );
        assert_eq!(workload_secret_journal_count(&authority), 1);
        let expected_values = match fault {
            Fault::BeforeEffect => {
                vec![b"synthetic-old".to_vec(), b"synthetic-new".to_vec()]
            }
            Fault::AfterEffect => vec![b"synthetic-new".to_vec()],
            Fault::None => unreachable!(),
        };
        assert_eq!(store.entry_values(), expected_values);

        store.clear_faults();
        let recovered = authority.list_user_workload_secrets().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(!recovered[0].protected_store_cleanup_pending);
        assert_eq!(
            workload_secret_rows(&authority),
            vec![("ROTATED".into(), 2, "ready".into())]
        );
        assert_eq!(workload_secret_journal_count(&authority), 0);
        assert_eq!(store.entry_values(), vec![b"synthetic-new".to_vec()]);
    }
}

#[test]
fn workload_secret_delete_recovers_in_live_authority_for_both_fault_timings() {
    for fault in [Fault::BeforeEffect, Fault::AfterEffect] {
        let temp = TempDir::new().expect("temporary directory");
        let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
        let authority =
            LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog())
                .unwrap();
        authority
            .set_user_workload_secret("DELETED", material(b"synthetic-delete"))
            .unwrap();

        store.set_delete_fault(fault);
        assert!(authority.delete_user_workload_secret("DELETED").is_err());
        assert_eq!(
            workload_secret_rows(&authority),
            vec![("DELETED".into(), 1, "pending_delete".into())]
        );
        assert_eq!(workload_secret_journal_count(&authority), 1);
        let expected_values = match fault {
            Fault::BeforeEffect => vec![b"synthetic-delete".to_vec()],
            Fault::AfterEffect => Vec::new(),
            Fault::None => unreachable!(),
        };
        assert_eq!(store.entry_values(), expected_values);

        store.clear_faults();
        assert!(authority.list_user_workload_secrets().unwrap().is_empty());
        assert!(workload_secret_rows(&authority).is_empty());
        assert_eq!(workload_secret_journal_count(&authority), 0);
        assert!(store.entry_values().is_empty());
    }
}

#[test]
fn ready_workload_secret_metadata_reads_do_not_access_protected_values() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog()).unwrap();
    let project = authority.create_secret_project("project").unwrap();
    authority
        .set_user_workload_secret("USER_SECRET", material(b"synthetic-user"))
        .unwrap();
    authority
        .set_project_workload_secret(project.id, "PROJECT_SECRET", material(b"synthetic-project"))
        .unwrap();

    store.set_get_fault(Fault::BeforeEffect);
    assert_eq!(authority.list_secret_projects().unwrap().len(), 1);
    assert_eq!(authority.list_user_workload_secrets().unwrap().len(), 1);
    assert_eq!(
        authority
            .list_project_workload_secrets(project.id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        authority
            .resolve_workload_secret_metadata(&WorkloadSecretSelection {
                project: Some("project".into()),
                user: true,
                ..WorkloadSecretSelection::default()
            })
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn invalid_workload_secret_requests_do_not_trigger_pending_reconciliation() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority =
        LocalCredentialAuthority::open(&authority_root(&temp), store.clone(), catalog()).unwrap();
    let project = authority.create_secret_project("project").unwrap();

    store.set_put_fault(Fault::AfterEffect);
    assert!(
        authority
            .set_user_workload_secret("PENDING", material(b"synthetic-pending"))
            .is_err()
    );
    store.clear_faults();
    let delete_calls = store.delete_call_count();

    assert_eq!(
        authority.set_user_workload_secret("INVALID-KEY", material(b"synthetic-value")),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.set_user_workload_secret("VALID_KEY", material(&[0xff])),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.delete_user_workload_secret("INVALID-KEY"),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.rename_user_workload_secret("PENDING", "INVALID-KEY"),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.set_project_workload_secret(
            project.id,
            "INVALID-KEY",
            material(b"synthetic-value"),
        ),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.delete_project_workload_secret(project.id, "INVALID-KEY"),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.rename_project_workload_secret(project.id, "VALID_KEY", "INVALID-KEY"),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.create_secret_project("invalid project"),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.resolve_workload_secret_metadata(&WorkloadSecretSelection {
            explicit_environment_keys: BTreeSet::from(["INVALID-KEY".into()]),
            ..WorkloadSecretSelection::default()
        }),
        Err(LocalCredentialError::InvalidWorkloadSecret)
    );
    assert_eq!(
        authority.resolve_workload_secret_metadata(&WorkloadSecretSelection {
            organization: true,
            ..WorkloadSecretSelection::default()
        }),
        Err(LocalCredentialError::OrganizationSecretsUnsupported)
    );

    assert_eq!(store.delete_call_count(), delete_calls);
    assert_eq!(
        workload_secret_rows(&authority),
        vec![("PENDING".into(), 1, "pending_write".into())]
    );
    assert_eq!(workload_secret_journal_count(&authority), 1);
    assert_eq!(store.entry_values(), vec![b"synthetic-pending".to_vec()]);
}
