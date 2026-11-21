//! An add's store write holds no lock another request waits on, and ends in
//! exactly one outcome (#5413).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind,
    EnvironmentAccessBinding, EnvironmentId, ProviderId,
};
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
};
use tempfile::TempDir;

use super::*;
use crate::{CredentialOperationLeaseRequest, NewCredential};

/// A bound for a loaded host. The proofs don't rest on it: each asserts the
/// held call is still held once the other requests have answered, so a
/// request that waited on it fails on that, not on this clock.
const PROMPT: Duration = Duration::from_secs(30);
/// How long a held `put` waits for the test before it lets itself go, well
/// past `PROMPT`, so a test that never releases it fails instead of hanging.
const HOLD: Duration = Duration::from_secs(120);

/// A store whose next `put`, once held, waits until the test lets it go, as
/// a keyring behind an unlock prompt nobody sees does (#5412).
#[derive(Clone, Default)]
struct HeldStore {
    inner: Arc<EphemeralProtectedStore>,
    gate: Arc<(Mutex<Gate>, Condvar)>,
    /// Every entry a `put` wrote.
    written: Arc<Mutex<Vec<ProtectedEntryId>>>,
}

#[derive(Default)]
struct Gate {
    held: bool,
    waiting: bool,
    /// The store refuses writes, and deletes, as a keyring past its bound
    /// does (#5271).
    refuse_put: bool,
    refuse_delete: bool,
}

impl HeldStore {
    fn hold_next_put(&self) {
        self.gate.0.lock().unwrap().held = true;
    }

    fn wait_for_held_put(&self) {
        let (lock, changed) = &*self.gate;
        let (gate, timeout) = changed
            .wait_timeout_while(lock.lock().unwrap(), PROMPT, |gate| !gate.waiting)
            .unwrap();
        assert!(!timeout.timed_out() && gate.waiting, "no put was held");
    }

    fn release(&self) {
        let (lock, changed) = &*self.gate;
        lock.lock().unwrap().held = false;
        changed.notify_all();
    }

    fn put_is_held(&self) -> bool {
        self.gate.0.lock().unwrap().waiting
    }

    fn refuse(&self, put: bool, delete: bool) {
        let mut gate = self.gate.0.lock().unwrap();
        gate.refuse_put = put;
        gate.refuse_delete = delete;
    }

    fn entries(&self, id: &ProtectedEntryId) -> bool {
        self.inner.get(id).unwrap().is_some()
    }
}

impl ProtectedStore for HeldStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.inner.get(id)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let (lock, changed) = &*self.gate;
        let mut gate = lock.lock().unwrap();
        if gate.held {
            gate.waiting = true;
            changed.notify_all();
            gate = changed
                .wait_timeout_while(gate, HOLD, |gate| gate.held)
                .unwrap()
                .0;
            gate.waiting = false;
        }
        if gate.refuse_put {
            return Err(ProtectedStoreError::TimedOut);
        }
        drop(gate);
        self.written.lock().unwrap().push(id.clone());
        self.inner.put(id, value)
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        if self.gate.0.lock().unwrap().refuse_delete {
            return Err(ProtectedStoreError::TimedOut);
        }
        self.inner.delete(id)
    }
}

fn authority(store: HeldStore) -> (TempDir, Arc<LocalCredentialAuthority<HeldStore>>) {
    let temp = TempDir::new().unwrap();
    let authority = LocalCredentialAuthority::open(
        &temp.path().join("authority"),
        store,
        codewire_access::builtin_provider_catalog(),
    )
    .unwrap();
    (temp, Arc::new(authority))
}

/// `call` on a thread of its own, waited for within the prompt bound: a
/// regression that blocks it fails the test instead of hanging it.
fn within<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> T {
    let (answer, answered) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = answer.send(call());
    });
    answered
        .recv_timeout(PROMPT)
        .expect("answered within the bound")
}

fn codex(name: &str) -> NewCredential {
    NewCredential {
        provider: ProviderId::parse("openai").unwrap(),
        authentication_kind: CredentialAuthKind::OAuth,
        display_name: name.to_owned(),
        account_hint: None,
        expires_at_unix: Some(4_102_444_800),
    }
}

fn material() -> ProtectedValue {
    ProtectedValue::from_slice(b"synthetic-oauth-token").unwrap()
}

fn rows(authority: &LocalCredentialAuthority<HeldStore>) -> i64 {
    authority
        .connection()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
        .unwrap()
}

/// An environment bound to a profile that selects `credential` for Codex,
/// and the lease admission its VM asks for.
fn bound_environment(
    authority: &LocalCredentialAuthority<HeldStore>,
    credential: &CredentialId,
) -> CredentialOperationLeaseRequest {
    let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").unwrap(),
            BTreeMap::from([(CapabilitySlot::codex(), credential.clone())]),
        )
        .unwrap();
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        })
        .unwrap();
    CredentialOperationLeaseRequest {
        environment_id,
        environment_generation: 7,
        capability_slot: CapabilitySlot::codex(),
        operation: BrokerOperationId::parse("responses").unwrap(),
        route: BrokerRouteId::parse("openai-api").unwrap(),
    }
}

/// While one add's write waits on the store, another command's listing and
/// a running VM's lease admission answer at once; the add then publishes.
#[test]
fn listing_and_lease_admission_answer_while_an_add_waits_on_the_store() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let lease = bound_environment(&authority, &work.metadata.id);

    store.hold_next_put();
    let adding = {
        let authority = Arc::clone(&authority);
        std::thread::spawn(move || authority.add_credential(codex("later"), material()))
    };
    store.wait_for_held_put();

    let listed = {
        let authority = Arc::clone(&authority);
        let id = work.metadata.id.clone();
        within(move || {
            authority
                .admit_environment_credential_operation(&lease)
                .unwrap();
            authority.get_credential(&id).unwrap();
            authority.list_credentials().unwrap()
        })
    };
    // They answered while the write was still waiting on the store.
    assert!(store.put_is_held());
    // The add being written is pending, so nothing lists it yet.
    assert_eq!(
        listed
            .iter()
            .map(|record| record.metadata.display_name.as_str())
            .collect::<Vec<_>>(),
        ["work"]
    );

    store.release();
    let later = within(move || adding.join().unwrap()).unwrap();
    assert!(store.entries(&protected_entry_id(&later.metadata.id, 1).unwrap()));
    assert_eq!(authority.list_credentials().unwrap().len(), 2);
}

/// An add whose request lapsed during the write, its deadline passed or the
/// authority shutting down, is not published: its material and its row are
/// gone, and the name is free again.
#[test]
fn an_add_whose_checks_fail_at_publication_is_not_published() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let checks = AtomicUsize::new(0);
    let lapsing = || match checks.fetch_add(1, Ordering::SeqCst) {
        0 => Ok(()),
        _ => Err(LocalCredentialError::SshEnrollmentClosed),
    };

    let refused = authority
        .add_credential_inner(codex("work"), material(), None, lapsing)
        .unwrap_err();

    assert_eq!(refused, LocalCredentialError::SshEnrollmentClosed);
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert_eq!(rows(&authority), 0);
    let written = store.written.lock().unwrap().clone();
    assert_eq!(written.len(), 1);
    assert!(!store.entries(&written[0]));
    authority.add_credential(codex("work"), material()).unwrap();
}

/// A second add of a name another add is still writing is refused as in
/// progress at once, instead of waiting behind it.
#[test]
fn an_add_of_a_name_still_being_written_is_refused_as_in_progress() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    store.hold_next_put();
    let adding = {
        let authority = Arc::clone(&authority);
        std::thread::spawn(move || authority.add_credential(codex("work"), material()))
    };
    store.wait_for_held_put();

    let refused = {
        let authority = Arc::clone(&authority);
        within(move || authority.add_credential(codex("WORK"), material()))
    }
    .unwrap_err();
    assert_eq!(refused, LocalCredentialError::CredentialAddInProgress);
    // Refused while the other add's write was still waiting on the store.
    assert!(store.put_is_held());

    store.release();
    within(move || adding.join().unwrap()).unwrap();
    assert_eq!(
        authority
            .add_credential(codex("work"), material())
            .unwrap_err(),
        LocalCredentialError::AlreadyExists
    );
}

/// A pending row no add is writing, left when the store refused both the
/// write and its cleanup (#5271), is refused as unfinished, never as one to
/// wait for: only start-up recovery removes it.
#[test]
fn a_pending_row_nothing_is_writing_is_refused_as_unfinished() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    store.refuse(true, true);
    assert_eq!(
        authority
            .add_credential(codex("work"), material())
            .unwrap_err(),
        LocalCredentialError::ProtectedStore(ProtectedStoreError::TimedOut)
    );
    assert_eq!(rows(&authority), 1);
    store.refuse(false, false);

    assert_eq!(
        authority
            .add_credential(codex("work"), material())
            .unwrap_err(),
        LocalCredentialError::CredentialAddUnfinished
    );
    assert!(authority.list_credentials().unwrap().is_empty());
}

/// An add whose caller goes away during the write still ends in one outcome:
/// the service runs it on a blocking worker, which publishes it.
#[test]
fn an_add_finishes_after_its_caller_is_gone() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    store.hold_next_put();
    let caller = {
        let authority = Arc::clone(&authority);
        runtime.spawn(crate::service::run_blocking(move || {
            authority.add_credential(codex("work"), material())
        }))
    };
    store.wait_for_held_put();
    caller.abort();
    runtime.block_on(async {
        assert!(caller.await.unwrap_err().is_cancelled());
    });

    store.release();
    let deadline = Instant::now() + PROMPT;
    while authority.list_credentials().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "the add never finished");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(rows(&authority), 1);
}
