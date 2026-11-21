//! A protected store whose next call can be held, as a keyring that stops
//! answering is, and the helpers the store-call tests share (#5412, #5413).

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use codewire_access::{
    AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind,
    EnvironmentAccessBinding, EnvironmentId, ProviderId,
};
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue,
};
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    CredentialId, CredentialOperationLeaseRequest, LocalCredentialAuthority, NewCredential,
};

/// A bound for a loaded host. The proofs don't rest on it: each asserts the
/// held call is still held once the other requests have answered, so a
/// request that waited on it fails on that, not on this clock.
pub(crate) const PROMPT: Duration = Duration::from_secs(30);
/// How long a held call waits for the test before it lets itself go, well
/// past `PROMPT`, so a test that never releases it fails instead of hanging.
const HOLD: Duration = Duration::from_secs(120);

/// The store call a test holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    Get,
    Put,
    Delete,
}

/// A store whose next call of one kind, once held, waits until the test lets
/// it go, as a keyring behind an unlock prompt nobody sees does (#5412).
#[derive(Clone, Default)]
pub(crate) struct HeldStore {
    pub(crate) inner: Arc<EphemeralProtectedStore>,
    gate: Arc<(Mutex<Gate>, Condvar)>,
    /// Every entry a `put` wrote.
    pub(crate) written: Arc<Mutex<Vec<ProtectedEntryId>>>,
}

#[derive(Default)]
struct Gate {
    held: Option<Call>,
    waiting: bool,
    /// The store refuses writes, and deletes, as a keyring past its bound
    /// does (#5271).
    refuse_put: bool,
    refuse_delete: bool,
}

impl HeldStore {
    pub(crate) fn hold_next(&self, call: Call) {
        self.gate.0.lock().unwrap().held = Some(call);
    }

    pub(crate) fn hold_next_put(&self) {
        self.hold_next(Call::Put);
    }

    pub(crate) fn wait_for_held(&self) {
        let (lock, changed) = &*self.gate;
        let (gate, timeout) = changed
            .wait_timeout_while(lock.lock().unwrap(), PROMPT, |gate| !gate.waiting)
            .unwrap();
        assert!(!timeout.timed_out() && gate.waiting, "no call was held");
    }

    pub(crate) fn wait_for_held_put(&self) {
        self.wait_for_held();
    }

    pub(crate) fn release(&self) {
        let (lock, changed) = &*self.gate;
        lock.lock().unwrap().held = None;
        changed.notify_all();
    }

    pub(crate) fn put_is_held(&self) -> bool {
        self.is_held()
    }

    /// Whether the held call is still waiting for the test.
    pub(crate) fn is_held(&self) -> bool {
        self.gate.0.lock().unwrap().waiting
    }

    /// Waits here while `call` is the one held.
    fn pass(&self, call: Call) -> std::sync::MutexGuard<'_, Gate> {
        let (lock, changed) = &*self.gate;
        let mut gate = lock.lock().unwrap();
        if gate.held == Some(call) {
            gate.waiting = true;
            changed.notify_all();
            gate = changed
                .wait_timeout_while(gate, HOLD, |gate| gate.held == Some(call))
                .unwrap()
                .0;
            gate.waiting = false;
        }
        gate
    }

    pub(crate) fn refuse(&self, put: bool, delete: bool) {
        let mut gate = self.gate.0.lock().unwrap();
        gate.refuse_put = put;
        gate.refuse_delete = delete;
    }

    pub(crate) fn entries(&self, id: &ProtectedEntryId) -> bool {
        self.inner.get(id).unwrap().is_some()
    }
}

impl ProtectedStore for HeldStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::OperatingSystem
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        drop(self.pass(Call::Get));
        self.inner.get(id)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let gate = self.pass(Call::Put);
        if gate.refuse_put {
            return Err(ProtectedStoreError::TimedOut);
        }
        drop(gate);
        self.written.lock().unwrap().push(id.clone());
        self.inner.put(id, value)
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        if self.pass(Call::Delete).refuse_delete {
            return Err(ProtectedStoreError::TimedOut);
        }
        self.inner.delete(id)
    }
}

pub(crate) fn authority(store: HeldStore) -> (TempDir, Arc<LocalCredentialAuthority<HeldStore>>) {
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
pub(crate) fn within<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> T {
    let (answer, answered) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = answer.send(call());
    });
    answered
        .recv_timeout(PROMPT)
        .expect("answered within the bound")
}

pub(crate) fn codex(name: &str) -> NewCredential {
    NewCredential {
        provider: ProviderId::parse("openai").unwrap(),
        authentication_kind: CredentialAuthKind::OAuth,
        display_name: name.to_owned(),
        account_hint: None,
        expires_at_unix: Some(4_102_444_800),
    }
}

pub(crate) fn material() -> ProtectedValue {
    ProtectedValue::from_slice(b"synthetic-oauth-token").unwrap()
}

pub(crate) fn rows(authority: &LocalCredentialAuthority<HeldStore>) -> i64 {
    authority
        .connection()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
        .unwrap()
}

/// An environment bound to a profile that selects `credential` for Codex,
/// and the lease admission its VM asks for.
pub(crate) fn bound_environment(
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
