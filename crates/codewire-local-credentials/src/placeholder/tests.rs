use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CREDENTIAL_PLACEHOLDER_TAG,
    CapabilityPolicy, CredentialAuthKind, GrantPermission, ProviderCatalog, ProviderDefinition,
    ProviderId,
};
use codewire_daemon_proto::codewire::bridge::v1::{
    CredentialBridgeGuestMessage, CredentialSshResponse,
};
use codewire_protected_store::ProtectedStorePersistence;
use codewire_protected_store::ssh_material::generate_ed25519;
use prost::Message as _;
use tempfile::TempDir;
use tokio_stream::{Stream, StreamExt as _};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

use super::*;
use crate::control::v1::local_credential_broker_lease_service_server::{
    LocalCredentialBrokerLeaseService, LocalCredentialBrokerLeaseServiceServer,
};
use crate::service::{credential_to_proto, derived_grant_to_proto};
use crate::{
    BrokerLeaseChannelError, LocalCredentialBrokerLeaseClient, NewCredential,
    serve_broker_lease_channel,
};

const OPERATION: &str = "responses";
const ROUTE: &str = "openai-api";
const SSH_OPERATION: &str = "ssh-sign";
const SSH_ROUTE: &str = "ssh-agent";

fn openai() -> CapabilitySlot {
    CapabilitySlot::openai()
}

fn codex() -> CapabilitySlot {
    CapabilitySlot::codex()
}

fn ssh() -> CapabilitySlot {
    CapabilitySlot::parse("ssh").unwrap()
}

/// One API-key provider that fills both the Codex and the OpenAI slot, and
/// an SSH key provider for the SSH slot.
fn catalog() -> ProviderCatalog {
    let policy = |kind, operation, route| CapabilityPolicy {
        authentication_kinds: BTreeSet::from([kind]),
        permissions: BTreeSet::from([GrantPermission {
            operation: BrokerOperationId::parse(operation).unwrap(),
            route: BrokerRouteId::parse(route).unwrap(),
        }]),
    };
    let api_key = policy(CredentialAuthKind::ApiKey, OPERATION, ROUTE);
    ProviderCatalog::from_definitions([
        ProviderDefinition {
            id: ProviderId::parse("openai").unwrap(),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
            capabilities: BTreeMap::from([(codex(), api_key.clone()), (openai(), api_key)]),
        },
        ProviderDefinition {
            id: ProviderId::parse("ssh").unwrap(),
            authentication_kinds: BTreeSet::from([CredentialAuthKind::SshKey]),
            capabilities: BTreeMap::from([(
                ssh(),
                policy(CredentialAuthKind::SshKey, SSH_OPERATION, SSH_ROUTE),
            )]),
        },
    ])
    .unwrap()
}

/// Whether `id` is an authority root's placeholder key entry.
fn is_key_entry(id: &ProtectedEntryId) -> bool {
    let reference = id.expose_reference();
    reference.starts_with("local/authority/") && reference.ends_with("/placeholder-key-v1")
}

/// What the store does with the placeholder key's entry.
#[derive(Default)]
struct KeyEntry {
    refuse_reads: Option<ProtectedStoreError>,
    refuse_next_read: Option<ProtectedStoreError>,
    refuse_writes: Option<ProtectedStoreError>,
    read_delay: Option<Duration>,
    /// Holds the next read: it reports that it has started on the first
    /// channel, then waits on the second.
    read_gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    reads: usize,
    writes: usize,
}

/// An in-memory operating-system store whose placeholder key entry can be
/// refused, slowed or held, with its reads and writes counted. Clones share state,
/// so an authority reopened on a clone sees the same entries.
#[derive(Clone, Default)]
struct Store {
    entries: Arc<Mutex<BTreeMap<ProtectedEntryId, Vec<u8>>>>,
    key: Arc<Mutex<KeyEntry>>,
}

impl Store {
    fn key_entry<T>(&self, operation: impl FnOnce(&mut KeyEntry) -> T) -> T {
        operation(&mut self.key.lock().unwrap())
    }

    /// The one authority's stored key.
    fn stored_key(&self) -> Option<Vec<u8>> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| is_key_entry(id))
            .map(|(_, value)| value.clone())
    }
}

impl ProtectedStore for Store {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        if is_key_entry(id) {
            let (delay, gate) = self.key_entry(|key| {
                key.reads += 1;
                match key.refuse_next_read.take().or(key.refuse_reads) {
                    Some(error) => Err(error),
                    None => Ok((key.read_delay, key.read_gate.take())),
                }
            })?;
            if let Some((started, release)) = gate {
                let _ = started.send(());
                let _ = release.recv();
            }
            if let Some(delay) = delay {
                std::thread::sleep(delay);
            }
        }
        self.entries
            .lock()
            .unwrap()
            .get(id)
            .map(|value| ProtectedValue::from_slice(value))
            .transpose()
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        if is_key_entry(id) {
            self.key_entry(|key| {
                key.writes += 1;
                key.refuse_writes.map_or(Ok(()), Err)
            })?;
        }
        self.entries
            .lock()
            .unwrap()
            .insert(id.clone(), value.expose_secret().to_vec());
        Ok(())
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.entries.lock().unwrap().remove(id);
        Ok(())
    }
}

struct Fixture {
    temp: TempDir,
    store: Store,
    authority: Arc<LocalCredentialAuthority<Store>>,
    first: CredentialId,
    second: CredentialId,
    /// Selects `second` in the Codex slot.
    second_profile: (codewire_access::AccessProfileId, u64),
    environment: EnvironmentId,
    other_environment: EnvironmentId,
}

/// Two environments bound to one profile that selects `first` in both the
/// Codex and the OpenAI slot. The store holds credential material and no
/// placeholder key, as every store before #3999 does.
fn fixture() -> Fixture {
    let temp = TempDir::new().unwrap();
    let store = Store::default();
    let authority = Arc::new(
        LocalCredentialAuthority::open(&temp.path().join("authority"), store.clone(), catalog())
            .unwrap(),
    );
    let add = |name: &str| {
        authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: name.into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(format!("synthetic-{name}").as_bytes()).unwrap(),
            )
            .unwrap()
            .metadata
            .id
    };
    let first = add("first");
    let second = add("second");
    let both = authority
        .create_profile(
            AccessProfileName::parse("both").unwrap(),
            BTreeMap::from([(codex(), first.clone()), (openai(), first.clone())]),
        )
        .unwrap()
        .profile;
    let second_profile = authority
        .create_profile(
            AccessProfileName::parse("second").unwrap(),
            BTreeMap::from([(codex(), second.clone())]),
        )
        .unwrap()
        .profile;
    let environment = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    let other_environment = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    for environment_id in [&environment, &other_environment] {
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: both.id.clone(),
                profile_revision: both.revision,
            })
            .unwrap();
    }
    Fixture {
        temp,
        store,
        authority,
        first,
        second,
        second_profile: (second_profile.id, second_profile.revision),
        environment,
        other_environment,
    }
}

fn request(
    environment_id: &EnvironmentId,
    environment_generation: u64,
    slot: CapabilitySlot,
) -> CredentialOperationLeaseRequest {
    CredentialOperationLeaseRequest {
        environment_id: environment_id.clone(),
        environment_generation,
        capability_slot: slot,
        operation: BrokerOperationId::parse(OPERATION).unwrap(),
        route: BrokerRouteId::parse(ROUTE).unwrap(),
    }
}

impl Fixture {
    fn lease(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: CapabilitySlot,
    ) -> CredentialOperationLease {
        self.authority
            .lease_environment_credential_operation(&request(
                environment_id,
                environment_generation,
                slot,
            ))
            .unwrap()
    }

    fn leased(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: CapabilitySlot,
    ) -> CredentialPlaceholder {
        self.lease(environment_id, environment_generation, slot)
            .placeholder()
            .unwrap()
            .clone()
    }

    /// The placeholder without a lease, for a generation started with the
    /// environment's current binding.
    fn unleased(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        slot: &CapabilitySlot,
        credential_id: &CredentialId,
    ) -> Result<CredentialPlaceholder, LocalCredentialError> {
        unleased_from(
            &self.authority,
            environment_id,
            environment_generation,
            slot,
            credential_id,
        )
    }

    /// Give the authority root its key entry and store `bytes` in it.
    fn set_stored_key(&self, bytes: &[u8]) {
        let entry = placeholder_key_entry(&self.authority.connection().unwrap()).unwrap();
        self.store
            .entries
            .lock()
            .unwrap()
            .insert(entry, bytes.to_vec());
    }
}

fn current_binding(
    authority: &LocalCredentialAuthority<Store>,
    environment_id: &EnvironmentId,
) -> Option<EnvironmentAccessBinding> {
    match authority.get_environment_access_binding(environment_id) {
        Ok(record) => Some(record.binding),
        Err(LocalCredentialError::EnvironmentBindingNotFound) => None,
        Err(error) => panic!("{error:?}"),
    }
}

fn unleased_from(
    authority: &LocalCredentialAuthority<Store>,
    environment_id: &EnvironmentId,
    environment_generation: u64,
    slot: &CapabilitySlot,
    credential_id: &CredentialId,
) -> Result<CredentialPlaceholder, LocalCredentialError> {
    authority.environment_credential_placeholder(
        environment_id,
        environment_generation,
        slot,
        credential_id,
        current_binding(authority, environment_id).as_ref(),
    )
}

#[test]
fn a_lease_carries_the_unleased_placeholder_once_the_key_is_loaded() {
    let fixture = fixture();
    // A lease never loads the key: before anything else has, it carries
    // none and touches no key entry.
    assert!(
        fixture
            .lease(&fixture.environment, 7, codex())
            .placeholder()
            .is_none()
    );
    assert_eq!(
        fixture.store.key_entry(|key| (key.reads, key.writes)),
        (0, 0)
    );
    assert!(fixture.store.stored_key().is_none());

    let unleased = fixture
        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
        .unwrap();
    assert!(CredentialPlaceholder::looks_like(unleased.as_str()));
    let leased = fixture.leased(&fixture.environment, 7, codex());
    assert!(leased.ct_eq(&unleased));
    assert!(
        fixture
            .leased(&fixture.environment, 7, codex())
            .ct_eq(&leased)
    );
    // Created once, read back once; leases read nothing more.
    assert_eq!(
        fixture.store.key_entry(|key| (key.reads, key.writes)),
        (2, 1)
    );
    assert_eq!(
        fixture.store.stored_key().map(|key| key.len()),
        Some(PLACEHOLDER_KEY_BYTES)
    );
}

#[test]
fn each_environment_generation_slot_and_credential_has_its_own_placeholder() {
    let fixture = fixture();
    let environment = &fixture.environment;
    let base = fixture
        .unleased(environment, 7, &codex(), &fixture.first)
        .unwrap();
    let other_slot = fixture.leased(environment, 7, openai());
    let other_environment = fixture.leased(&fixture.other_environment, 7, codex());
    let next_generation = fixture.leased(environment, 8, codex());
    // An older generation stays derivable, leased and unleased, after a newer
    // one, and its placeholder is what it was.
    assert!(fixture.leased(environment, 7, codex()).ct_eq(&base));
    assert!(
        fixture
            .unleased(environment, 7, &codex(), &fixture.first)
            .unwrap()
            .ct_eq(&base)
    );
    let (profile_id, revision) = &fixture.second_profile;
    let binding = fixture
        .authority
        .get_environment_access_binding(environment)
        .unwrap()
        .binding;
    fixture
        .authority
        .replace_environment_access_binding(
            environment,
            &binding.profile_id,
            binding.profile_revision,
            profile_id.clone(),
            *revision,
        )
        .unwrap();
    let other_credential = fixture.leased(environment, 8, codex());
    assert!(
        fixture
            .unleased(environment, 8, &codex(), &fixture.second)
            .unwrap()
            .ct_eq(&other_credential)
    );

    let all = [
        &base,
        &other_slot,
        &other_environment,
        &next_generation,
        &other_credential,
    ];
    for (index, left) in all.iter().enumerate() {
        for right in &all[index + 1..] {
            assert!(!left.ct_eq(right));
        }
    }
    // The older generation's lease now names the newly bound credential.
    assert!(
        fixture
            .unleased(environment, 7, &codex(), &fixture.second)
            .unwrap()
            .ct_eq(&fixture.leased(environment, 7, codex()))
    );
    assert_eq!(fixture.store.key_entry(|key| key.writes), 1);
}

#[test]
fn the_placeholder_is_the_same_after_the_authority_restarts() {
    let fixture = fixture();
    let unleased = fixture
        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
        .unwrap();
    let older = fixture
        .unleased(&fixture.environment, 3, &codex(), &fixture.first)
        .unwrap();
    let root = fixture.temp.path().join("authority");
    let Fixture {
        temp: _temp,
        store,
        authority,
        first,
        environment,
        ..
    } = fixture;
    drop(authority);
    let reopened = LocalCredentialAuthority::open(&root, store.clone(), catalog()).unwrap();
    assert!(
        unleased_from(&reopened, &environment, 7, &codex(), &first)
            .unwrap()
            .ct_eq(&unleased)
    );
    assert!(
        unleased_from(&reopened, &environment, 3, &codex(), &first)
            .unwrap()
            .ct_eq(&older)
    );
    let lease = reopened
        .lease_environment_credential_operation(&request(&environment, 7, codex()))
        .unwrap();
    assert!(lease.placeholder().unwrap().ct_eq(&unleased));
    assert_eq!(
        store.key_entry(|key| key.writes),
        1,
        "the key is created once"
    );
}

#[test]
fn a_stored_key_is_used_as_it_is() {
    let fixture = fixture();
    // Built at run time: a key of one repeated byte.
    let key_bytes = [0x2a_u8; PLACEHOLDER_KEY_BYTES];
    fixture.set_stored_key(&key_bytes);
    let expected = CredentialPlaceholder::derive(
        &PlaceholderKey::from_slice(&key_bytes).unwrap(),
        &fixture.environment,
        7,
        &codex(),
        &fixture.first,
    );
    assert!(
        fixture
            .unleased(&fixture.environment, 7, &codex(), &fixture.first)
            .unwrap()
            .ct_eq(&expected)
    );
    assert_eq!(fixture.store.key_entry(|key| key.writes), 0);
}

/// A corrupt key would otherwise fail every placeholder for good. Its
/// replacement changes every placeholder, which fails closed.
#[test]
fn a_corrupt_key_is_replaced_like_an_absent_one() {
    let short = [0x2a_u8; PLACEHOLDER_KEY_BYTES - 1];
    let valid = [0x2a_u8; PLACEHOLDER_KEY_BYTES];
    // A value of the wrong length, and a value the store reports corrupt.
    for (stored, reported) in [
        (&short[..], None),
        (&valid[..], Some(ProtectedStoreError::CorruptEntry)),
    ] {
        let fixture = fixture();
        fixture.set_stored_key(stored);
        fixture
            .store
            .key_entry(|key| key.refuse_next_read = reported);
        let placeholder = fixture
            .unleased(&fixture.environment, 7, &codex(), &fixture.first)
            .unwrap();
        let replaced = fixture.store.stored_key().unwrap();
        assert_eq!(replaced.len(), PLACEHOLDER_KEY_BYTES);
        assert!(replaced != stored, "the key was not replaced");
        assert_eq!(fixture.store.key_entry(|key| key.writes), 1);
        let expected = CredentialPlaceholder::derive(
            &PlaceholderKey::from_slice(&replaced).unwrap(),
            &fixture.environment,
            7,
            &codex(),
            &fixture.first,
        );
        assert!(placeholder.ct_eq(&expected));
        assert!(
            fixture
                .leased(&fixture.environment, 7, codex())
                .ct_eq(&placeholder)
        );
    }
}

#[test]
fn a_key_that_cannot_be_loaded_leaves_the_lease_as_it_was() {
    let fixture = fixture();
    let authority = &fixture.authority;
    let lease_request = request(&fixture.environment, 7, codex());
    let binding = authority
        .get_environment_access_binding(&fixture.environment)
        .unwrap()
        .binding;
    for (refuse_reads, refuse_writes, error) in [
        (
            Some(ProtectedStoreError::AccessDenied),
            None,
            ProtectedStoreError::AccessDenied,
        ),
        (
            None,
            Some(ProtectedStoreError::TimedOut),
            ProtectedStoreError::TimedOut,
        ),
    ] {
        fixture.store.key_entry(|key| {
            key.refuse_reads = refuse_reads;
            key.refuse_writes = refuse_writes;
        });
        assert_eq!(
            fixture
                .unleased(&fixture.environment, 7, &codex(), &fixture.first)
                .err(),
            Some(LocalCredentialError::ProtectedStore(error))
        );

        let (admission, placeholder) = authority
            .admit_environment_credential_lease(&lease_request)
            .unwrap();
        assert!(placeholder.is_none());
        assert_eq!(
            admission,
            authority
                .admit_environment_credential_operation(&lease_request)
                .unwrap()
        );
        let (selected, placeholder) = authority
            .admit_selected_environment_credential_lease(&lease_request, Some(&binding))
            .unwrap();
        assert!(placeholder.is_none());
        assert_eq!(
            selected,
            authority
                .admit_selected_environment_credential_operation(&lease_request, Some(&binding))
                .unwrap()
        );
        let lease = authority
            .lease_environment_credential_operation(&lease_request)
            .unwrap();
        assert!(lease.placeholder().is_none());
        assert_eq!(lease.credential, admission.credential);
        assert_eq!(lease.grant, admission.grant);
        assert_eq!(lease.permission, admission.permission);
        assert_eq!(lease.material_generation(), admission.material_generation);
        assert!(lease.with_material(|material| material == b"synthetic-first"));
    }
    assert!(fixture.store.stored_key().is_none());

    // Nothing was kept from a failure: the next use loads the key.
    fixture.store.key_entry(|key| {
        key.refuse_reads = None;
        key.refuse_writes = None;
    });
    let unleased = fixture
        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
        .unwrap();
    assert!(
        fixture
            .leased(&fixture.environment, 7, codex())
            .ct_eq(&unleased)
    );
}

#[test]
fn two_first_uses_create_one_key() {
    let fixture = fixture();
    // Each read of the key entry waits, so the second use arrives while the
    // first is still loading.
    fixture
        .store
        .key_entry(|key| key.read_delay = Some(Duration::from_millis(50)));
    let barrier = Barrier::new(2);
    let [left, right] = std::thread::scope(|scope| {
        [(), ()]
            .map(|()| {
                scope.spawn(|| {
                    barrier.wait();
                    fixture
                        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
                        .unwrap()
                })
            })
            .map(|handle| handle.join().unwrap())
    });
    assert!(left.ct_eq(&right));
    assert_eq!(fixture.store.key_entry(|key| key.writes), 1);
}

#[test]
fn the_unleased_placeholder_is_refused_wherever_a_lease_is() {
    let fixture = fixture();
    let authority = &fixture.authority;
    let unbound = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    let anthropic = CapabilitySlot::anthropic();
    for (environment_id, slot, credential_id, error) in [
        (
            &unbound,
            codex(),
            &fixture.first,
            LocalCredentialError::EnvironmentBindingNotFound,
        ),
        (
            &fixture.environment,
            anthropic,
            &fixture.first,
            LocalCredentialError::CredentialOperationLeaseDenied,
        ),
    ] {
        assert_eq!(
            authority
                .lease_environment_credential_operation(&request(environment_id, 7, slot.clone()))
                .unwrap_err(),
            error
        );
        assert_eq!(
            fixture
                .unleased(environment_id, 7, &slot, credential_id)
                .err(),
            Some(error)
        );
    }
    // A credential the environment's binding does not select in that slot.
    assert_eq!(
        fixture
            .unleased(&fixture.environment, 7, &codex(), &fixture.second)
            .err(),
        Some(LocalCredentialError::CredentialOperationLeaseDenied)
    );

    // An SSH key, which a lease refuses outside the typed SSH operation.
    let ssh_key = authority
        .add_ssh_credential("ssh".into(), None, generate_ed25519().unwrap(), || Ok(()))
        .unwrap()
        .metadata
        .id;
    let profile = authority
        .create_profile(
            AccessProfileName::parse("ssh").unwrap(),
            BTreeMap::from([(ssh(), ssh_key.clone())]),
        )
        .unwrap()
        .profile;
    let ssh_environment = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    let ssh_binding = EnvironmentAccessBinding {
        environment_id: ssh_environment.clone(),
        profile_id: profile.id,
        profile_revision: profile.revision,
    };
    authority
        .create_environment_access_binding(ssh_binding.clone())
        .unwrap();
    // Admission grants the SSH slot; the lease refuses the key after it.
    let ssh_request = CredentialOperationLeaseRequest {
        environment_id: ssh_environment.clone(),
        environment_generation: 7,
        capability_slot: ssh(),
        operation: BrokerOperationId::parse(SSH_OPERATION).unwrap(),
        route: BrokerRouteId::parse(SSH_ROUTE).unwrap(),
    };
    assert!(
        authority
            .admit_selected_environment_credential_lease(&ssh_request, Some(&ssh_binding))
            .is_ok()
    );
    let leased = authority
        .lease_environment_credential_operation(&ssh_request)
        .unwrap_err();
    assert_eq!(leased, LocalCredentialError::CredentialOperationLeaseDenied);
    assert_eq!(
        fixture
            .unleased(&ssh_environment, 7, &ssh(), &ssh_key)
            .err(),
        Some(leased)
    );

    // A generation started with another binding than the environment's now:
    // none, or another environment's.
    let lease_request = request(&fixture.environment, 7, codex());
    for stale in [None, Some(&ssh_binding)] {
        let leased = authority
            .admit_selected_environment_credential_lease(&lease_request, stale)
            .unwrap_err();
        assert_eq!(leased, LocalCredentialError::StaleEnvironmentBinding);
        assert_eq!(
            authority
                .environment_credential_placeholder(
                    &fixture.environment,
                    7,
                    &codex(),
                    &fixture.first,
                    stale,
                )
                .err(),
            Some(leased)
        );
    }

    authority.revoke_credential(&fixture.first).unwrap();
    let leased = authority
        .lease_environment_credential_operation(&request(&fixture.environment, 7, codex()))
        .unwrap_err();
    assert_eq!(
        fixture
            .unleased(&fixture.environment, 7, &codex(), &fixture.first)
            .err(),
        Some(leased)
    );
    assert_eq!(
        fixture.store.key_entry(|key| (key.reads, key.writes)),
        (0, 0),
        "a refusal loads no key"
    );
}

/// A lease admitted while the first key load waits on the store is neither
/// delayed by it nor given a placeholder.
#[test]
fn a_lease_admitted_while_the_key_loads_is_not_delayed_and_carries_none() {
    const BOUND: Duration = Duration::from_secs(30);
    let fixture = fixture();
    let (started, load_started) = mpsc::channel();
    let (release, released) = mpsc::channel();
    fixture
        .store
        .key_entry(|key| key.read_gate = Some((started, released)));
    let loading = {
        let authority = Arc::clone(&fixture.authority);
        let environment = fixture.environment.clone();
        let first = fixture.first.clone();
        std::thread::spawn(move || unleased_from(&authority, &environment, 7, &codex(), &first))
    };
    load_started
        .recv_timeout(BOUND)
        .expect("the key load never reached the store");

    let (leased, lease_done) = mpsc::channel();
    {
        let authority = Arc::clone(&fixture.authority);
        let lease_request = request(&fixture.environment, 7, codex());
        // Detached: if the lease waits for the load, the bound below fails
        // the test rather than hanging it.
        std::thread::spawn(move || {
            let _ = leased.send(
                authority
                    .lease_environment_credential_operation(&lease_request)
                    .map(|lease| lease.placeholder().is_none()),
            );
        });
    }
    let carries_none = lease_done
        .recv_timeout(BOUND)
        .expect("the lease waited for the key load");
    assert_eq!(carries_none, Ok(true));

    release.send(()).unwrap();
    let unleased = loading.join().unwrap().unwrap();
    assert!(
        fixture
            .leased(&fixture.environment, 7, codex())
            .ct_eq(&unleased)
    );
}

/// `BrokerLeaseResponse` exactly as every authority and broker before #3999
/// declare it: without the placeholder field.
#[derive(Clone, PartialEq, prost::Message)]
struct BrokerLeaseResponseBeforePlaceholders {
    #[prost(message, optional, tag = "1")]
    credential: Option<v1::Credential>,
    #[prost(message, optional, tag = "2")]
    grant: Option<v1::DerivedGrant>,
    #[prost(message, optional, tag = "3")]
    permission: Option<v1::GrantPermission>,
    #[prost(uint64, tag = "4")]
    material_generation: u64,
}

/// The response the authority sends for one admitted lease.
fn lease_response(fixture: &Fixture) -> v1::BrokerLeaseResponse {
    let (admission, placeholder) = fixture
        .authority
        .admit_environment_credential_lease(&request(&fixture.environment, 7, codex()))
        .unwrap();
    v1::BrokerLeaseResponse {
        credential: Some(credential_to_proto(admission.credential)),
        grant: Some(derived_grant_to_proto(admission.grant)),
        permission: Some(v1::GrantPermission {
            operation: admission.permission.operation.to_string(),
            route: admission.permission.route.to_string(),
        }),
        material_generation: admission.material_generation,
        placeholder: placeholder
            .map(|placeholder| placeholder.as_str().to_owned())
            .unwrap_or_default(),
    }
}

/// The lease protocol keeps its version: an older broker decodes a response
/// that carries a placeholder, and a response from an older authority is
/// byte for byte one that carries none.
#[test]
fn the_placeholder_field_is_compatible_in_both_directions() {
    let fixture = fixture();
    let without = lease_response(&fixture);
    assert!(without.placeholder.is_empty());
    let older = BrokerLeaseResponseBeforePlaceholders {
        credential: without.credential.clone(),
        grant: without.grant.clone(),
        permission: without.permission.clone(),
        material_generation: without.material_generation,
    };
    // An older authority's response is the same bytes as a response with no
    // placeholder, and decodes to none.
    assert_eq!(older.encode_to_vec(), without.encode_to_vec());
    let decoded = v1::BrokerLeaseResponse::decode(older.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, without);
    assert!(lease_response_placeholder(&decoded).is_none());

    let expected = fixture
        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
        .unwrap();
    let with = lease_response(&fixture);
    assert_eq!(with.placeholder, expected.as_str());
    let encoded = with.encode_to_vec();
    assert!(
        lease_response_placeholder(&v1::BrokerLeaseResponse::decode(encoded.as_slice()).unwrap())
            .unwrap()
            .ct_eq(&expected)
    );
    // An older broker skips the field it does not know.
    assert_eq!(
        BrokerLeaseResponseBeforePlaceholders::decode(encoded.as_slice()).unwrap(),
        older
    );
}

impl Fixture {
    /// One Codex lease over a broker channel serving `environment_generation`.
    async fn channel_lease(&self, environment_generation: u64) -> CredentialOperationLease {
        let binding = self
            .authority
            .get_environment_access_binding(&self.environment)
            .unwrap()
            .binding;
        let (server_stream, client_stream) = tokio::net::UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_lease_channel(
            Arc::clone(&self.authority),
            server_stream,
            self.environment.clone(),
            environment_generation,
            Some(binding),
        ));
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            self.store.clone(),
            self.environment.clone(),
            environment_generation,
        )
        .await
        .unwrap();
        let lease = client
            .lease_operation(
                Uuid::new_v4(),
                codex(),
                BrokerOperationId::parse(OPERATION).unwrap(),
                BrokerRouteId::parse(ROUTE).unwrap(),
            )
            .await
            .unwrap();
        drop(client);
        server.abort();
        lease
    }
}

#[tokio::test]
async fn a_channel_lease_carries_the_authoritys_placeholder_once_loaded() {
    let fixture = fixture();
    let before = fixture.channel_lease(7).await;
    assert!(before.placeholder().is_none());
    assert_eq!(before.credential.metadata.id, fixture.first);
    assert!(before.with_material(|material| material == b"synthetic-first"));

    let expected = fixture
        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
        .unwrap();
    let lease = fixture.channel_lease(7).await;
    assert!(lease.placeholder().unwrap().ct_eq(&expected));
    assert!(!format!("{lease:?}").contains(expected.as_str()));
}

/// A broker lease channel that answers every lease with one fixed response.
struct FixedLeaseResponse(v1::BrokerLeaseResponse);

type NoDelegation =
    Pin<Box<dyn Stream<Item = Result<v1::BrokerDelegationResponse, Status>> + Send>>;

#[tonic::async_trait]
impl LocalCredentialBrokerLeaseService for FixedLeaseResponse {
    type DelegateCredentialsStream = NoDelegation;

    async fn delegate_credentials(
        &self,
        _: Request<Streaming<CredentialBridgeGuestMessage>>,
    ) -> Result<Response<NoDelegation>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn ssh_operation(
        &self,
        _: Request<v1::BrokerSshRequest>,
    ) -> Result<Response<CredentialSshResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn project_environment(
        &self,
        _: Request<v1::BrokerEnvironmentProjectionRequest>,
    ) -> Result<Response<v1::BrokerEnvironmentProjectionResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn report_broker_ready(
        &self,
        _: Request<v1::BrokerReadyRequest>,
    ) -> Result<Response<v1::BrokerReadyResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn lease_credential_operation(
        &self,
        _: Request<v1::BrokerLeaseRequest>,
    ) -> Result<Response<v1::BrokerLeaseResponse>, Status> {
        Ok(Response::new(self.0.clone()))
    }

    async fn begin_credential_refresh(
        &self,
        _: Request<v1::BrokerCredentialRefreshRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshAdmission>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn start_credential_refresh(
        &self,
        _: Request<v1::BrokerCredentialRefreshStartRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshStartResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn commit_credential_refresh(
        &self,
        _: Request<v1::BrokerCredentialRefreshCommitRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshCommitResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn abort_credential_refresh(
        &self,
        _: Request<v1::BrokerCredentialRefreshAbortRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshAbortResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }

    async fn fail_credential_refresh(
        &self,
        _: Request<v1::BrokerCredentialRefreshFailureRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshFailureResponse>, Status> {
        Err(Status::unimplemented("not under test"))
    }
}

impl Fixture {
    /// One Codex lease over a channel whose authority answers with
    /// `response`.
    async fn lease_answered_with(
        &self,
        response: v1::BrokerLeaseResponse,
    ) -> Result<CredentialOperationLease, BrokerLeaseChannelError> {
        let (server_stream, client_stream) = tokio::net::UnixStream::pair().unwrap();
        let server = tokio::spawn(
            Server::builder()
                .add_service(LocalCredentialBrokerLeaseServiceServer::new(
                    FixedLeaseResponse(response),
                ))
                .serve_with_incoming(
                    tokio_stream::once(Ok::<_, std::io::Error>(server_stream))
                        .chain(tokio_stream::pending()),
                ),
        );
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            self.store.clone(),
            self.environment.clone(),
            7,
        )
        .await
        .unwrap();
        let lease = client
            .lease_operation(
                Uuid::new_v4(),
                codex(),
                BrokerOperationId::parse(OPERATION).unwrap(),
                BrokerRouteId::parse(ROUTE).unwrap(),
            )
            .await;
        drop(client);
        server.abort();
        lease
    }
}

/// A placeholder never fails a lease: a value the broker cannot read, from
/// a later authority or a broken one, is no placeholder and the lease is
/// otherwise the same.
#[tokio::test]
async fn a_lease_with_an_unreadable_placeholder_succeeds_and_carries_none() {
    let fixture = fixture();
    let placeholder = fixture
        .unleased(&fixture.environment, 7, &codex(), &fixture.first)
        .unwrap();
    let response = lease_response(&fixture);
    assert_eq!(response.placeholder, placeholder.as_str());
    let body = &placeholder.as_str()[CREDENTIAL_PLACEHOLDER_TAG.len()..];

    let lease = fixture.lease_answered_with(response.clone()).await.unwrap();
    assert!(lease.placeholder().unwrap().ct_eq(&placeholder));

    for unreadable in [
        format!("cwp2_{body}"),
        "garbage".to_owned(),
        " ".to_owned(),
        placeholder.as_str()[..47].to_owned(),
        format!("{}=", &placeholder.as_str()[..47]),
        format!("{}{}", placeholder.as_str(), "A".repeat(4096)),
    ] {
        let lease = fixture
            .lease_answered_with(v1::BrokerLeaseResponse {
                placeholder: unreadable.clone(),
                ..response.clone()
            })
            .await
            .unwrap_or_else(|error| panic!("{unreadable:?} failed the lease: {error:?}"));
        assert!(lease.placeholder().is_none(), "{unreadable:?}");
        assert_eq!(lease.credential.metadata.id, fixture.first);
        assert!(lease.with_material(|material| material == b"synthetic-first"));
    }
}
