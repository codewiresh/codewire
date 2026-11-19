//! A local connect against the real authority: the store is probed before
//! any provider step, and what a failed save says (#4826).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use codewire_access::builtin_provider_catalog;
use codewire_local_credentials::{AuthorityRuntimeConfig, LocalCredentialClient};
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue,
};

use super::super::CredentialConnectProviderArg;
use super::tests::connect_ready_authority;
use super::*;

/// An ephemeral store that refuses every write while `refusal` is set, and
/// holds every write unanswered while it is frozen, as a stuck keyring does.
#[derive(Clone, Default)]
struct Store {
    inner: Arc<EphemeralProtectedStore>,
    refusal: Arc<Mutex<Option<ProtectedStoreError>>>,
    frozen: Arc<(Mutex<bool>, Condvar)>,
    held: Arc<AtomicBool>,
}

impl Store {
    fn freeze(&self) -> Thaw {
        *self.frozen.0.lock().unwrap() = true;
        Thaw(self.clone())
    }
}

/// Thaws the store when dropped, so a failed test never leaves the
/// authority's worker waiting.
struct Thaw(Store);

impl Drop for Thaw {
    fn drop(&mut self) {
        *self.0.frozen.0.lock().unwrap() = false;
        self.0.frozen.1.notify_all();
    }
}

impl ProtectedStore for Store {
    fn persistence(&self) -> ProtectedStorePersistence {
        ProtectedStorePersistence::ProcessLifetime
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.inner.get(id)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        let mut frozen = self.frozen.0.lock().unwrap();
        while *frozen {
            self.held.store(true, Ordering::SeqCst);
            frozen = self.frozen.1.wait(frozen).unwrap();
        }
        drop(frozen);
        match *self.refusal.lock().unwrap() {
            Some(error) => Err(error),
            None => self.inner.put(id, value),
        }
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.inner.delete(id)
    }
}

struct Authority {
    _temp: tempfile::TempDir,
    config: AuthorityRuntimeConfig,
    server: tokio::task::JoinHandle<Result<(), codewire_local_credentials::AuthorityRuntimeError>>,
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn serve(store: Store) -> (Authority, LocalCredentialClient) {
    let temp = tempfile::tempdir().unwrap();
    let config = AuthorityRuntimeConfig {
        root: temp.path().join("authority"),
        executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        socket_dir: temp.path().join("authority"),
    };
    let server = tokio::spawn(
        codewire_local_credentials::serve_local_credential_authority(
            config.clone(),
            store,
            builtin_provider_catalog(),
        ),
    );
    let client = connect_ready_authority(&config, &server).await;
    (
        Authority {
            _temp: temp,
            config,
            server,
        },
        client,
    )
}

/// A locked store refuses the local connect's readiness check, which says so
/// in a save's words, so the connect stops before the sign-in starts; a
/// store that accepts the write answers it and keeps nothing.
#[tokio::test]
async fn a_store_that_refuses_a_write_is_not_ready_for_a_sign_in() {
    let store = Store::default();
    *store.refusal.lock().unwrap() = Some(ProtectedStoreError::AccessDenied);
    let (_authority, mut client) = serve(store.clone()).await;
    let error = LocalConnectStore {
        store_check_explained: false,
        client: &mut client,
        json: false,
    }
    .ready(CredentialConnectProviderArg::Claude, "work")
    .await
    .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("is locked") && text.contains("so your Claude sign-in wasn't saved"),
        "{text}"
    );
    assert!(!text.contains("locked or inaccessible"), "{text}");
    assert!(!text.contains("code:"), "{text}");
    assert!(client.list_credentials().await.unwrap().is_empty());

    *store.refusal.lock().unwrap() = None;
    LocalConnectStore {
        store_check_explained: false,
        client: &mut client,
        json: false,
    }
    .ready(CredentialConnectProviderArg::Claude, "work")
    .await
    .unwrap();
    assert!(client.list_credentials().await.unwrap().is_empty());
}

/// A store that times out or is unavailable stops the connect in a save's
/// words, never the store's (#5271), and nothing is saved.
#[tokio::test]
async fn a_store_that_times_out_or_is_unavailable_is_not_ready() {
    for (error, words) in [
        (
            ProtectedStoreError::TimedOut,
            "didn't answer within 2 minutes, so your Codex sign-in wasn't saved",
        ),
        (
            ProtectedStoreError::Unavailable,
            "the local credential store refused your Codex sign-in, so nothing was saved",
        ),
    ] {
        let store = Store::default();
        *store.refusal.lock().unwrap() = Some(error);
        let (_authority, mut client) = serve(store).await;
        let text = format!(
            "{:#}",
            LocalConnectStore {
                store_check_explained: false,
                client: &mut client,
                json: false,
            }
            .ready(CredentialConnectProviderArg::Codex, "work")
            .await
            .unwrap_err()
        );
        assert!(text.contains(words), "{text}");
        // The store's own message is for the log, never the person.
        assert!(!text.contains("protected storage"), "{text}");
        assert!(!text.contains("code:"), "{text}");
        assert!(client.list_credentials().await.unwrap().is_empty());
    }
}

/// Stderr that thaws the store once the waiting line is written, so the
/// listing can only answer after the line, however slowly the test runs.
struct ThawOnWrite {
    written: Vec<u8>,
    thaw: Option<Thaw>,
}

impl std::io::Write for ThawOnWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(bytes);
        self.thaw.take();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A keyring that stops answering holds the authority for as long as it
/// waits, so another command's first call waits behind it: here the name
/// check `add` makes before it asks for the key. That wait shows the waiting
/// line within a second, never a silent pause (#5271).
#[tokio::test]
async fn a_call_behind_a_frozen_keyring_shows_the_waiting_line() {
    let store = Store::default();
    let thaw = store.freeze();
    let (authority, mut client) = serve(store.clone()).await;
    let mut doctor = connect_ready_authority(&authority.config, &authority.server).await;
    let probe = tokio::spawn(async move { doctor.probe_protected_store().await });
    tokio::time::timeout(Duration::from_secs(30), async {
        while !store.held.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the probe reached the frozen keyring");

    let mut stderr = ThawOnWrite {
        written: Vec::new(),
        thaw: Some(thaw),
    };
    let screen = store_wait::Screen {
        live: false,
        ascii: false,
    };
    // Without the line the store never thaws, so this bound turns a hang
    // into a failure.
    let listing = tokio::time::timeout(
        Duration::from_secs(30),
        store_wait::waiting_on(&mut stderr, screen, client.list_credentials()),
    )
    .await
    .expect("the waiting line was written and the store thawed");
    assert!(listing.unwrap().is_empty());
    // The words themselves are pinned in store_wait's tests.
    assert_eq!(
        String::from_utf8(stderr.written).unwrap(),
        format!("{}\n", store_wait::plain_line())
    );
    probe.await.unwrap().unwrap();
}
