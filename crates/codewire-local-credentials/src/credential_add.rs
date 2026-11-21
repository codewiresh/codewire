//! Adding a credential: its pending row, the store write and the row's
//! publication (#5413).
//!
//! No protected-store call runs while the metadata connection is held, so a
//! keyring that stops answering, behind an unlock prompt nobody sees, holds
//! up this add alone. Listing, admission and a running VM's lease never wait
//! on it.
//!
//! The publication boundary is three things together, where it used to be one
//! lock held from the checks to `ready`:
//! - a `pending_write` row that nothing else reads or changes;
//! - the checks made again when the row is published;
//! - the final update guarded by the state it expects.
//!
//! So nothing is `ready` without its material, and a caller told the add
//! failed never finds the credential afterwards.

use super::*;

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// `publication_check` holds the request's own conditions (enrollment
    /// admission, shutdown and the RPC's deadline). It runs when the pending
    /// row is created and again when the row is published.
    pub(super) fn add_credential_inner(
        &self,
        input: NewCredential,
        material: ProtectedValue,
        ssh_public_key: Option<SshPublicKeyMetadata>,
        publication_check: impl Fn() -> Result<(), LocalCredentialError>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let provider =
            self.catalog
                .get(&input.provider)
                .ok_or_else(|| AccessError::ProviderUnavailable {
                    provider: input.provider.clone(),
                })?;
        if !provider.supports_authentication_kind(input.authentication_kind) {
            return Err(AccessError::UnsupportedAuthenticationKind {
                provider: input.provider,
                kind: input.authentication_kind,
            }
            .into());
        }

        credential_names::admit_new_name(&input.display_name)?;
        let input = claude_token::admit(input, &material)?;
        // The authority makes the id, never the caller, so the entry it names
        // is fresh and nothing else can create it: the collision check needs
        // no lock.
        let id = CredentialId::parse(Uuid::new_v4().to_string())?;
        let metadata = CredentialMetadata {
            id: id.clone(),
            placement: Placement::Local,
            owner: Owner::User(self.owner_id.clone()),
            provider: input.provider,
            authentication_kind: input.authentication_kind,
            display_name: input.display_name,
            account_hint: input.account_hint,
            ssh_public_key,
            status: CredentialStatus::Active,
            expires_at_unix: input.expires_at_unix,
            revocation_generation: 1,
        };
        metadata.validate()?;
        let entry_id = protected_entry_id(&id, 1)?;
        match self.protected_store.get(&entry_id) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LocalCredentialError::ProtectedEntryCollision),
            Err(error) => return Err(error.into()),
        }
        let _in_flight =
            self.insert_pending_credential(&metadata, &entry_id, &publication_check)?;

        // From here the add ends in exactly one of: `ready`; its material and
        // row deleted; or, when the store does not answer, its row left for
        // start-up recovery (#5271). The service runs it on a blocking
        // worker, so a caller that goes away does not stop it.
        if let Err(error) = self.protected_store.put(&entry_id, &material) {
            self.undo_pending_credential(&id, &entry_id)?;
            return Err(error.into());
        }
        let connection = self.connection()?;
        if let Err(error) = publication_check() {
            drop(connection);
            self.undo_pending_credential(&id, &entry_id)?;
            return Err(error);
        }
        let changed = connection
            .execute(
                "UPDATE credentials
                 SET material_state = 'ready', updated_at_unix_ms = ?2
                 WHERE id = ?1 AND material_state = 'pending_write'",
                params![
                    id.as_str(),
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_internal_credential(&connection, &id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    /// The pending row, after the request's checks, under one connection
    /// hold, and the add recorded as in flight until it ends. A name or a
    /// GitHub connection held by a pending row is refused as in progress
    /// when its add is still writing, so the person waits, and as unfinished
    /// when nothing is, since only start-up recovery removes that row.
    fn insert_pending_credential(
        &self,
        metadata: &CredentialMetadata,
        entry_id: &ProtectedEntryId,
        publication_check: &impl Fn() -> Result<(), LocalCredentialError>,
    ) -> Result<AddInFlight<'_>, LocalCredentialError> {
        let persistence = persistence_to_str(self.protected_store.persistence());
        let connection = self.connection()?;
        publication_check()?;
        // GitHub is one connection per store. A second one fails closed; the
        // existing connection is reconnected in place or deleted first.
        if metadata.provider.as_str() == "github"
            && metadata.authentication_kind == CredentialAuthKind::OAuth
            && github_connection_exists(&connection)?
        {
            return Err(match pending_github_connection(&connection)? {
                Some(pending) => self.pending_add_refusal(&pending),
                None => LocalCredentialError::GitHubAlreadyConnected,
            });
        }
        let now = i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?;
        let inserted = connection.execute(
            "INSERT INTO credentials(
               id, provider, authentication_kind, display_name, account_hint,
               ssh_public_key_openssh, ssh_public_key_fingerprint,
               status, expires_at_unix, revocation_generation,
               material_generation, protected_entry_id, store_persistence, material_state,
               created_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?12, ?13, ?14, ?14)",
            params![
                metadata.id.as_str(),
                metadata.provider.as_str(),
                auth_kind_to_str(metadata.authentication_kind),
                metadata.display_name,
                metadata.account_hint,
                metadata
                    .ssh_public_key
                    .as_ref()
                    .map(|key| key.openssh.as_str()),
                metadata
                    .ssh_public_key
                    .as_ref()
                    .map(|key| key.fingerprint.as_str()),
                status_to_str(metadata.status),
                optional_u64_to_i64(metadata.expires_at_unix)?,
                i64::try_from(metadata.revocation_generation)
                    .map_err(|_| LocalCredentialError::InvalidTime)?,
                entry_id.expose_reference(),
                persistence,
                MaterialState::PendingWrite.as_str(),
                now,
            ],
        );
        if let Err(error) = inserted {
            return Err(match pending_name(&connection, metadata)? {
                Some(pending) => self.pending_add_refusal(&pending),
                None => map_insert_error(error),
            });
        }
        self.adds_in_flight
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?
            .insert(metadata.id.clone());
        Ok(AddInFlight {
            authority_adds: &self.adds_in_flight,
            id: metadata.id.clone(),
        })
    }

    /// In progress while that pending row's add is still writing, and
    /// unfinished once nothing is.
    fn pending_add_refusal(&self, pending: &CredentialId) -> LocalCredentialError {
        match self.adds_in_flight.lock() {
            Ok(in_flight) if in_flight.contains(pending) => {
                LocalCredentialError::CredentialAddInProgress
            }
            _ => LocalCredentialError::CredentialAddUnfinished,
        }
    }

    /// The material first, then the row, and the row only once the material
    /// is gone: a row left pending is start-up recovery's (#5271), which only
    /// ever deletes.
    fn undo_pending_credential(
        &self,
        id: &CredentialId,
        entry_id: &ProtectedEntryId,
    ) -> Result<(), LocalCredentialError> {
        if self.protected_store.delete(entry_id).is_ok() {
            delete_pending_write(&*self.connection()?, id)?;
        }
        Ok(())
    }
}

/// An add recorded as in flight, until it ends however it ends.
struct AddInFlight<'a> {
    authority_adds: &'a Mutex<BTreeSet<CredentialId>>,
    id: CredentialId,
}

impl Drop for AddInFlight<'_> {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.authority_adds.lock() {
            in_flight.remove(&self.id);
        }
    }
}

/// The pending row of the store's GitHub connection, if its add has not
/// published.
fn pending_github_connection(
    connection: &Connection,
) -> Result<Option<CredentialId>, LocalCredentialError> {
    pending_id(connection.query_row(
        "SELECT id FROM credentials
         WHERE provider = 'github' AND authentication_kind = 'oauth'
           AND material_state = 'pending_write'",
        [],
        |row| row.get::<_, String>(0),
    ))
}

/// The pending row of a credential of this provider and name, if its add has
/// not published.
fn pending_name(
    connection: &Connection,
    metadata: &CredentialMetadata,
) -> Result<Option<CredentialId>, LocalCredentialError> {
    pending_id(connection.query_row(
        "SELECT id FROM credentials
         WHERE provider = ?1 AND display_name = ?2 COLLATE NOCASE
           AND material_state = 'pending_write'",
        params![metadata.provider.as_str(), metadata.display_name],
        |row| row.get::<_, String>(0),
    ))
}

fn pending_id(
    row: Result<String, rusqlite::Error>,
) -> Result<Option<CredentialId>, LocalCredentialError> {
    match row {
        Ok(id) => CredentialId::parse(id)
            .map(Some)
            .map_err(|_| LocalCredentialError::CorruptMetadata),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(database_error(error)),
    }
}

#[cfg(test)]
mod tests;
