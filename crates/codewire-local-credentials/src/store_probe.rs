//! The store-write probe: before a provider sign-in is spent, the authority
//! checks that the store it saves credentials to accepts a write (#4826).

use codewire_protected_store::{ProtectedEntryId, ProtectedStore, ProtectedValue};

use crate::{LocalCredentialAuthority, LocalCredentialError};

/// The probe's one entry. Credential material lives under
/// `local/credentials/` and the placeholder key under `local/authority/`, so
/// the canary never names, overwrites or deletes either.
const STORE_PROBE_ENTRY: &str = "local/store-probe/canary-v1";
const STORE_PROBE_VALUE: &[u8] = b"codewire-store-probe-canary";

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Write the canary to the store that holds this authority's credentials
    /// and delete it again. Probes are ordered among themselves; they hold no
    /// metadata lock, since they touch no row, so a store that stops answering
    /// holds up no other request (#5413). The delete runs even when the write
    /// failed, in case the store kept part of it; the write's error is the
    /// answer.
    pub(crate) fn probe_protected_store(&self) -> Result<(), LocalCredentialError> {
        let _serialized = self
            .store_probe
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        let entry = ProtectedEntryId::parse(STORE_PROBE_ENTRY)?;
        let value = ProtectedValue::from_slice(STORE_PROBE_VALUE)?;
        let written = self.protected_store.put(&entry, &value);
        let deleted = self.protected_store.delete(&entry);
        written?;
        deleted?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use codewire_protected_store::{
        EphemeralProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::NewCredential;

    /// An ephemeral store that refuses writes while `refusal` is set, and
    /// records every entry the authority touched.
    #[derive(Clone, Default)]
    struct Store {
        inner: Arc<EphemeralProtectedStore>,
        refusal: Arc<Mutex<Option<ProtectedStoreError>>>,
        delete_refusal: Arc<Mutex<Option<ProtectedStoreError>>>,
        touched: Arc<Mutex<Vec<String>>>,
    }

    impl ProtectedStore for Store {
        fn persistence(&self) -> ProtectedStorePersistence {
            ProtectedStorePersistence::OperatingSystem
        }

        fn get(
            &self,
            id: &ProtectedEntryId,
        ) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
            self.inner.get(id)
        }

        fn put(
            &self,
            id: &ProtectedEntryId,
            value: &ProtectedValue,
        ) -> Result<(), ProtectedStoreError> {
            self.touched
                .lock()
                .unwrap()
                .push(id.expose_reference().to_owned());
            match *self.refusal.lock().unwrap() {
                Some(error) => Err(error),
                None => self.inner.put(id, value),
            }
        }

        fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
            match *self.delete_refusal.lock().unwrap() {
                Some(error) => Err(error),
                None => self.inner.delete(id),
            }
        }
    }

    fn authority(store: Store) -> (TempDir, LocalCredentialAuthority<Store>) {
        let temp = TempDir::new().unwrap();
        let authority = LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            store,
            codewire_access::builtin_provider_catalog(),
        )
        .unwrap();
        (temp, authority)
    }

    #[test]
    fn the_probe_writes_and_removes_only_its_canary_and_leaves_credentials_alone() {
        let store = Store::default();
        let (_temp, authority) = authority(store.clone());
        let saved = authority
            .add_credential(
                NewCredential {
                    provider: codewire_access::ProviderId::parse("openai").unwrap(),
                    authentication_kind: codewire_access::CredentialAuthKind::ApiKey,
                    display_name: "work".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-openai-key").unwrap(),
            )
            .unwrap();
        let credential_entry = crate::protected_entry_id(&saved.metadata.id, 1).unwrap();
        store.touched.lock().unwrap().clear();

        authority.probe_protected_store().unwrap();

        assert_eq!(
            *store.touched.lock().unwrap(),
            vec![STORE_PROBE_ENTRY.to_owned()]
        );
        let canary = ProtectedEntryId::parse(STORE_PROBE_ENTRY).unwrap();
        assert!(store.inner.get(&canary).unwrap().is_none());
        assert_eq!(
            store
                .inner
                .get(&credential_entry)
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"synthetic-openai-key"
        );
    }

    #[test]
    fn a_store_that_refuses_the_write_answers_the_probe_with_its_error() {
        let store = Store::default();
        let (_temp, authority) = authority(store.clone());
        *store.refusal.lock().unwrap() = Some(ProtectedStoreError::AccessDenied);
        assert_eq!(
            authority.probe_protected_store(),
            Err(LocalCredentialError::ProtectedStore(
                ProtectedStoreError::AccessDenied
            ))
        );
        let canary = ProtectedEntryId::parse(STORE_PROBE_ENTRY).unwrap();
        assert!(store.inner.get(&canary).unwrap().is_none());
    }

    /// A store that takes the write but refuses the delete answers the probe
    /// with that refusal: it isn't ready, and nothing else is touched.
    #[test]
    fn a_store_that_refuses_the_canarys_delete_answers_the_probe_with_its_error() {
        let store = Store::default();
        let (_temp, authority) = authority(store.clone());
        *store.delete_refusal.lock().unwrap() = Some(ProtectedStoreError::AccessDenied);
        assert_eq!(
            authority.probe_protected_store(),
            Err(LocalCredentialError::ProtectedStore(
                ProtectedStoreError::AccessDenied
            ))
        );
        assert_eq!(
            *store.touched.lock().unwrap(),
            vec![STORE_PROBE_ENTRY.to_owned()]
        );
    }
}
