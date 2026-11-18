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

/// A locked store answers the local connect's readiness check with its own
/// sentence, so the connect stops before the sign-in starts; a store that
/// accepts the write answers it and keeps nothing.
#[tokio::test]
async fn a_store_that_refuses_a_write_is_not_ready_for_a_sign_in() {
    let store = Store::default();
    *store.refusal.lock().unwrap() = Some(ProtectedStoreError::AccessDenied);
    let (_authority, mut client) = serve(store.clone()).await;
    let error = LocalConnectStore {
        client: &mut client,
    }
    .ready(CredentialConnectProviderArg::Claude)
    .await
    .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("can't save a Claude sign-in now, so nothing was saved"),
        "{text}"
    );
    assert!(text.contains("locked or inaccessible"), "{text}");
    assert!(!text.contains("code:"), "{text}");
    assert!(client.list_credentials().await.unwrap().is_empty());

    *store.refusal.lock().unwrap() = None;
    LocalConnectStore {
        client: &mut client,
    }
    .ready(CredentialConnectProviderArg::Claude)
    .await
    .unwrap();
    assert!(client.list_credentials().await.unwrap().is_empty());
}

/// A store that times out or is unavailable stops the connect with the
/// authority's own words for it, and nothing is saved.
#[tokio::test]
async fn a_store_that_times_out_or_is_unavailable_is_not_ready() {
    for (error, words) in [
        (
            ProtectedStoreError::TimedOut,
            "local protected storage did not respond in time",
        ),
        (
            ProtectedStoreError::Unavailable,
            "local credential authority storage is unavailable",
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
            .ready(CredentialConnectProviderArg::Codex)
            .await
            .unwrap_err()
        );
        assert!(
            text.contains("can't save a Codex sign-in now, so nothing was saved"),
            "{text}"
        );
        assert!(text.contains(words), "{text}");
        assert!(client.list_credentials().await.unwrap().is_empty());
    }
}
