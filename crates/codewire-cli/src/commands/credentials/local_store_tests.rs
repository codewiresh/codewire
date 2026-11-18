//! A local connect against the real authority: the store is probed before
//! any provider step, and what a failed save says (#4826).

use std::sync::{Arc, Mutex};

use codewire_access::builtin_provider_catalog;
use codewire_local_credentials::{AuthorityRuntimeConfig, LocalCredentialClient};
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStore, ProtectedStoreError,
    ProtectedStorePersistence, ProtectedValue,
};

use super::super::CredentialConnectProviderArg;
use super::tests::connect_ready_authority;
use super::*;

/// An ephemeral store that refuses every write while `refusal` is set.
#[derive(Clone, Default)]
struct Store {
    inner: Arc<EphemeralProtectedStore>,
    refusal: Arc<Mutex<Option<ProtectedStoreError>>>,
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
        client: &mut client,
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
        client: &mut client,
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
                client: &mut client,
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
