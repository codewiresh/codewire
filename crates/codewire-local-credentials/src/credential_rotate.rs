//! Rotating a credential's material behind the same id (#5413).
//!
//! The rotation holds the refresh-owner lock throughout, so no other change
//! to this credential's material interleaves with it, and works on the
//! material connection, whose store calls never run inside a transaction. The
//! metadata connection is never held across them, so a revoke, a listing or
//! a VM's lease answers while the store waits. A revoke that lands meanwhile
//! wins: the rotation's guarded update then changes no row, and the rotation
//! rolls back what it wrote.

use super::*;

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Atomically make a new protected value active behind the same credential
    /// ID. The old value remains active until the new entry and metadata commit
    /// are durable. Failure to delete the retired entry is journaled and
    /// reported through metadata without making the new value unavailable.
    /// The caller must supply the exact observed revision. An absent account
    /// hint clears the previous hint; callers preserving it must pass it back.
    pub fn rotate_credential_material(
        &self,
        id: &CredentialId,
        expected_revocation_generation: u64,
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
        account_hint: Option<String>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        // Hold the refresh-owner lock through every journal and protected-store
        // mutation. A check-then-unlock here would let a broker begin a refresh
        // against the same next material generation while a manual rotation is
        // still in flight.
        let active_refreshes = self
            .active_refreshes
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        if active_refreshes.contains_key(id) {
            return Err(LocalCredentialError::CredentialRefreshInProgress);
        }
        let connection = self.material_connection()?;
        let store = MaterialStore::new(&connection, &self.protected_store);
        let mut current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if current.public.metadata.provider.as_str() == "ssh"
            || current.public.metadata.authentication_kind == CredentialAuthKind::SshKey
        {
            return Err(LocalCredentialError::SshCredentialRequiresEnrollment);
        }
        if expected_revocation_generation == 0
            || current.public.metadata.revocation_generation != expected_revocation_generation
        {
            // Even journal reconciliation can delete or promote protected
            // material. A stale caller has no authority to initiate it.
            return Err(LocalCredentialError::StaleCredentialRevision);
        }
        let mut replacement_metadata = current.public.metadata.clone();
        replacement_metadata.account_hint = account_hint;
        claude_token::set_expiry(&mut replacement_metadata, &material, expires_at_unix)?;
        replacement_metadata.status = CredentialStatus::Active;
        replacement_metadata.validate()?;
        let expires_at = optional_u64_to_i64(replacement_metadata.expires_at_unix)?;
        reconcile_ready_journal(&store, &current)?;
        current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if current.public.metadata.revocation_generation != expected_revocation_generation {
            // Recovery may have promoted an abandoned OAuth refresh. Do not
            // replace that newer result using an earlier confirmation.
            return Err(LocalCredentialError::StaleCredentialRevision);
        }

        let material_generation = current
            .material_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let next_entry_id = protected_entry_id(id, material_generation)?;
        if store.get(&next_entry_id)?.is_some() {
            return Err(LocalCredentialError::ProtectedEntryCollision);
        }
        let rotation = Rotation {
            id,
            expected_revocation_generation,
            material_generation,
            next_entry_id,
            retired_entry_id: current.protected_entry_id.clone(),
            expires_at,
            account_hint: replacement_metadata.account_hint,
            now: unix_millis()?,
        };
        insert_protected_entry_journal(
            &connection,
            id,
            JournalOperation::RollbackWrite,
            &rotation.next_entry_id,
            rotation.now,
        )?;

        let published = store
            .put(&rotation.next_entry_id, &material)
            .and_then(|()| rotation.publish(&connection));
        if let Err(error) = published {
            rotation.roll_back(&store)?;
            return Err(error);
        }
        if store.delete(&rotation.retired_entry_id).is_ok() {
            delete_protected_entry_journal(&connection, id)?;
        }
        drop(active_refreshes);
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }
}

/// One rotation's new state, published in one transaction or rolled back.
struct Rotation<'a> {
    id: &'a CredentialId,
    expected_revocation_generation: u64,
    material_generation: u64,
    next_entry_id: ProtectedEntryId,
    retired_entry_id: ProtectedEntryId,
    expires_at: Option<i64>,
    account_hint: Option<String>,
    now: u64,
}

impl Rotation<'_> {
    /// One IMMEDIATE transaction holds the guarded update, the reason when it
    /// changes no row, and the journal's move to `delete_retired`, so a
    /// rotation that lost a race never leaves a row naming the current entry
    /// as retired. Nothing in it calls the store.
    fn publish(&self, connection: &Connection) -> Result<(), LocalCredentialError> {
        let to_i64 =
            |value: u64| i64::try_from(value).map_err(|_| LocalCredentialError::CorruptMetadata);
        let transaction = immediate(connection)?;
        let changed = transaction
            .execute(
                "UPDATE credentials
                 SET protected_entry_id = ?2, status = 'active', expires_at_unix = ?3,
                     revocation_generation = ?4, material_generation = ?5,
                     updated_at_unix_ms = ?6, account_hint = ?7
                 WHERE id = ?1 AND material_state = 'ready' AND revocation_generation = ?8",
                params![
                    self.id.as_str(),
                    self.next_entry_id.expose_reference(),
                    self.expires_at,
                    to_i64(self.expected_revocation_generation + 1)?,
                    to_i64(self.material_generation)?,
                    to_i64(self.now)?,
                    self.account_hint,
                    to_i64(self.expected_revocation_generation)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(self.lost_to(&transaction)?);
        }
        let journal_changed = transaction
            .execute(
                "UPDATE protected_entry_journal
                 SET operation = 'delete_retired', protected_entry_id = ?2
                 WHERE credential_id = ?1 AND operation = 'rollback_write'",
                params![self.id.as_str(), self.retired_entry_id.expose_reference()],
            )
            .map_err(database_error)?;
        if journal_changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        transaction.commit().map_err(database_error)
    }

    /// What the guarded update lost to, read in its own transaction: a
    /// revoke moved the revision, or the credential is no longer `ready`.
    fn lost_to(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<LocalCredentialError, LocalCredentialError> {
        let row: Option<(String, i64)> = transaction
            .query_row(
                "SELECT material_state, revocation_generation FROM credentials WHERE id = ?1",
                [self.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        Ok(match row {
            Some((state, generation))
                if state == MaterialState::Ready.as_str()
                    && u64::try_from(generation).ok()
                        != Some(self.expected_revocation_generation) =>
            {
                LocalCredentialError::StaleCredentialRevision
            }
            Some((state, _)) if state == MaterialState::Ready.as_str() => {
                LocalCredentialError::CorruptMetadata
            }
            _ => LocalCredentialError::CredentialUnavailable,
        })
    }

    /// Only this rotation's own next entry, never the current one; the entry
    /// first, then its journal row, and the row only once the entry is gone.
    /// A row left behind is the only record of the entry, which start-up
    /// recovery then deletes.
    fn roll_back<S: ProtectedStore>(
        &self,
        store: &MaterialStore<'_, S>,
    ) -> Result<(), LocalCredentialError> {
        if store.delete(&self.next_entry_id).is_ok() {
            delete_protected_entry_journal(store.connection(), self.id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
