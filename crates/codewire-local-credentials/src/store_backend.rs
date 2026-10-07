//! The authority records which persistent store holds its protected values
//! and moves them, once, when the configured store changes. A store is a
//! backend plus, for an explicit test keychain, its path; a previous store is
//! always opened at its recorded location, never at the configured one.
//!
//! A switch copies each exact entry the metadata references, reads it back
//! and compares it, and only then records the new store. Any failure before
//! that commit removes the copies it made and leaves the recorded store and
//! every original value untouched. After the commit the old store's copies
//! are deleted; entries that could not be deleted yet stay listed in a
//! per-store retirement record and are retried at every start.

use std::collections::BTreeSet;

use codewire_protected_store::{ProtectedEntryId, ProtectedStore, ProtectedStoreError};
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::{AuthorityProtectedStore, LocalCredentialError, database_error};

const STORE_KEY: &str = "store_backend";
const RETIRING_STORE_PREFIX: &str = "store_backend_retiring/";

pub(crate) type OpenProtectedStore<'a> =
    &'a dyn Fn(&AuthorityProtectedStore) -> Result<Box<dyn ProtectedStore>, ProtectedStoreError>;

/// Make `selected` the recorded store of this authority, moving existing
/// values from the recorded one. A database without a record predates the
/// record and used the platform default backend.
pub(crate) fn select_protected_store(
    connection: &Connection,
    selected: &AuthorityProtectedStore,
    store: &dyn ProtectedStore,
    open: OpenProtectedStore<'_>,
) -> Result<(), LocalCredentialError> {
    retire_previous_stores(connection, selected, open)?;
    let recorded = recorded_store(connection)?;
    let current = recorded
        .clone()
        .or_else(AuthorityProtectedStore::platform_default)
        .unwrap_or_else(|| selected.clone());
    if &current == selected {
        if recorded.is_none() {
            record_store(connection, selected, None)?;
        }
        return Ok(());
    }
    let entries = referenced_entries(connection)?;
    let moved = if entries.is_empty() {
        Vec::new()
    } else {
        let previous = open(&current).map_err(LocalCredentialError::ProtectedStoreSwitch)?;
        copy_entries(&*previous, store, &entries)
            .map_err(LocalCredentialError::ProtectedStoreSwitch)?
    };
    record_store(connection, selected, Some((&current, &moved)))?;
    if !moved.is_empty() {
        // A failure keeps the retirement record for the next start; the
        // values are already committed to the selected store.
        let _ = try_retire(connection, &current, &moved, open);
    }
    Ok(())
}

fn copy_entries(
    from: &dyn ProtectedStore,
    to: &dyn ProtectedStore,
    entries: &BTreeSet<ProtectedEntryId>,
) -> Result<Vec<ProtectedEntryId>, ProtectedStoreError> {
    let mut copied = Vec::new();
    let result = (|| {
        for id in entries {
            let Some(value) = from.get(id)? else {
                continue;
            };
            copied.push(id.clone());
            to.put(id, &value)?;
            match to.get(id)? {
                Some(stored) if stored.expose_secret() == value.expose_secret() => {}
                _ => return Err(ProtectedStoreError::CorruptEntry),
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(copied),
        Err(error) => {
            // Nothing is recorded yet; the original backend stays authoritative.
            for id in &copied {
                let _ = to.delete(id);
            }
            Err(error)
        }
    }
}

fn retire_previous_stores(
    connection: &Connection,
    selected: &AuthorityProtectedStore,
    open: OpenProtectedStore<'_>,
) -> Result<(), LocalCredentialError> {
    let markers = {
        let mut statement = connection
            .prepare("SELECT key, value FROM authority_metadata WHERE key GLOB ?1 ORDER BY key")
            .map_err(database_error)?;
        statement
            .query_map([format!("{RETIRING_STORE_PREFIX}*")], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?
    };
    for (key, value) in markers {
        let retiring = key
            .strip_prefix(RETIRING_STORE_PREFIX)
            .and_then(AuthorityProtectedStore::from_record)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let entries = serde_json::from_str::<Vec<String>>(&value)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?
            .into_iter()
            .map(|entry| {
                ProtectedEntryId::parse(entry).map_err(|_| LocalCredentialError::CorruptMetadata)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Err(error) = try_retire(connection, &retiring, &entries, open)
            && &retiring == selected
        {
            // Switching back into a store whose stale copies still await
            // deletion would let that deletion remove the new values.
            return Err(LocalCredentialError::ProtectedStoreSwitch(error));
        }
    }
    Ok(())
}

fn try_retire(
    connection: &Connection,
    retiring: &AuthorityProtectedStore,
    entries: &[ProtectedEntryId],
    open: OpenProtectedStore<'_>,
) -> Result<(), ProtectedStoreError> {
    let store = open(retiring)?;
    for id in entries {
        store.delete(id)?;
    }
    connection
        .execute(
            "DELETE FROM authority_metadata WHERE key = ?1",
            [retiring_key(retiring)],
        )
        .map_err(|_| ProtectedStoreError::Unavailable)?;
    Ok(())
}

fn retiring_key(store: &AuthorityProtectedStore) -> String {
    format!("{RETIRING_STORE_PREFIX}{}", store.to_record())
}

fn recorded_store(
    connection: &Connection,
) -> Result<Option<AuthorityProtectedStore>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT value FROM authority_metadata WHERE key = ?1",
            [STORE_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|value| {
            AuthorityProtectedStore::from_record(&value)
                .ok_or(LocalCredentialError::CorruptMetadata)
        })
        .transpose()
}

fn record_store(
    connection: &Connection,
    selected: &AuthorityProtectedStore,
    retiring: Option<(&AuthorityProtectedStore, &[ProtectedEntryId])>,
) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![STORE_KEY, selected.to_record()],
        )
        .map_err(database_error)?;
    if let Some((store, entries)) = retiring.filter(|(_, entries)| !entries.is_empty()) {
        let entries = entries
            .iter()
            .map(|id| id.expose_reference())
            .collect::<Vec<_>>();
        let changed = transaction
            .execute(
                "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)",
                params![
                    retiring_key(store),
                    serde_json::to_string(&entries)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
    }
    transaction.commit().map_err(database_error)
}

fn referenced_entries(
    connection: &Connection,
) -> Result<BTreeSet<ProtectedEntryId>, LocalCredentialError> {
    let mut statement = connection
        .prepare(
            "SELECT protected_entry_id FROM credentials
             UNION SELECT protected_entry_id FROM protected_entry_journal
             UNION SELECT protected_entry_id FROM workload_secrets
             UNION SELECT protected_entry_id FROM workload_secret_journal",
        )
        .map_err(database_error)?;
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(database_error)?
        .map(|entry| {
            let entry = entry.map_err(database_error)?;
            ProtectedEntryId::parse(entry).map_err(|_| LocalCredentialError::CorruptMetadata)
        })
        .collect()
}

#[cfg(test)]
mod tests;
