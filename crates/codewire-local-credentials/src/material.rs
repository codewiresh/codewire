//! The one place the material paths call the protected store (#5413).
//!
//! A material path holds the material connection while it works, but a store
//! call must never run inside an open SQL transaction on it: that would hold
//! the database's write lock while a keyring waits, and every other request's
//! write would wait behind it. So each store call checks the connection is in
//! autocommit, and refuses otherwise.

use codewire_access::{CredentialId, CredentialStatus};
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStorePersistence, ProtectedValue,
};
use rusqlite::Connection;

use crate::{LocalCredentialAuthority, LocalCredentialError, MaterialState};

pub(crate) struct MaterialStore<'a, S> {
    connection: &'a Connection,
    store: &'a S,
}

impl<'a, S: ProtectedStore> MaterialStore<'a, S> {
    pub(crate) fn new(connection: &'a Connection, store: &'a S) -> Self {
        Self { connection, store }
    }

    /// The connection the path's SQL runs on.
    pub(crate) fn connection(&self) -> &'a Connection {
        self.connection
    }

    pub(crate) fn get(
        &self,
        id: &ProtectedEntryId,
    ) -> Result<Option<ProtectedValue>, LocalCredentialError> {
        self.outside_transaction()?;
        Ok(self.store.get(id)?)
    }

    pub(crate) fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), LocalCredentialError> {
        self.outside_transaction()?;
        Ok(self.store.put(id, value)?)
    }

    pub(crate) fn delete(&self, id: &ProtectedEntryId) -> Result<(), LocalCredentialError> {
        self.outside_transaction()?;
        Ok(self.store.delete(id)?)
    }

    /// The store's lifetime: a property of the store, not a call to it.
    pub(crate) fn persistence(&self) -> ProtectedStorePersistence {
        self.store.persistence()
    }

    fn outside_transaction(&self) -> Result<(), LocalCredentialError> {
        if self.connection.is_autocommit() {
            Ok(())
        } else {
            Err(LocalCredentialError::StoreCallInTransaction)
        }
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// The one value an executor's lease carries (#4984): the entry of
    /// generation `generation` of `id`, read only while that is the
    /// credential's current generation and its status is `status`. The checks
    /// run before the store is read, on the material connection, and the read
    /// runs outside any transaction on it (#5413).
    pub(crate) fn executor_lease_material(
        &self,
        id: &CredentialId,
        generation: u64,
        status: CredentialStatus,
    ) -> Result<ProtectedValue, LocalCredentialError> {
        self.lease_material_in(id, generation, status, MaterialState::Ready)
    }

    /// As [`Self::executor_lease_material`], for a credential a delete has
    /// revoked and moved out of `ready` (#6128); its material stays until
    /// the delete removes it.
    pub(crate) fn deleting_lease_material(
        &self,
        id: &CredentialId,
        generation: u64,
    ) -> Result<ProtectedValue, LocalCredentialError> {
        self.lease_material_in(
            id,
            generation,
            CredentialStatus::Revoked,
            MaterialState::PendingDelete,
        )
    }

    fn lease_material_in(
        &self,
        id: &CredentialId,
        generation: u64,
        status: CredentialStatus,
        material_state: MaterialState,
    ) -> Result<ProtectedValue, LocalCredentialError> {
        let connection = self.material_connection()?;
        let current = crate::load_internal_credential(&connection, id, Some(material_state))?;
        if current.material_generation != generation || current.public.metadata.status != status {
            return Err(LocalCredentialError::CredentialUnavailable);
        }
        MaterialStore::new(&connection, &self.protected_store)
            .get(&current.protected_entry_id)?
            .ok_or(LocalCredentialError::CredentialMaterialMissing)
    }
}

#[cfg(test)]
mod tests;
