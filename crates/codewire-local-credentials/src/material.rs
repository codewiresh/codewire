//! The one place the material paths call the protected store (#5413).
//!
//! A material path holds the material connection while it works, but a store
//! call must never run inside an open SQL transaction on it: that would hold
//! the database's write lock while a keyring waits, and every other request's
//! write would wait behind it. So each store call checks the connection is in
//! autocommit, and refuses otherwise.

use codewire_protected_store::{ProtectedEntryId, ProtectedStore, ProtectedValue};
use rusqlite::Connection;

use crate::LocalCredentialError;

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

    fn outside_transaction(&self) -> Result<(), LocalCredentialError> {
        if self.connection.is_autocommit() {
            Ok(())
        } else {
            Err(LocalCredentialError::StoreCallInTransaction)
        }
    }
}

#[cfg(test)]
mod tests;
