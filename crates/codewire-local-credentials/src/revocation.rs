//! Revoking a local credential: its status, never its material, which stays
//! until the credential is deleted.

use rusqlite::params;

use super::*;

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    pub fn revoke_credential(
        &self,
        id: &CredentialId,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        revoke_on(&connection, id)
    }

    /// Revokes the credential for a provider revocation (#4717), under one
    /// hold of the authority's connection: the record after the revoke, the
    /// material generation a revocation executor may read (revoking keeps
    /// the material until delete), and whether the credential was active
    /// before. There is no generation to read when a refresh had started, or
    /// its marker can't be read: its exchange may have rotated the stored
    /// token, so the provider's answer would not be about the live one.
    pub(crate) fn revoke_for_provider(
        &self,
        id: &CredentialId,
    ) -> Result<(CredentialRecord, Option<u64>, bool), LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        let was_active = current.public.metadata.status == CredentialStatus::Active;
        let unrotated = matches!(
            load_credential_refresh_marker(&connection, id),
            Ok(None)
                | Ok(Some(CredentialRefreshJournal {
                    phase: CredentialRefreshPhase::Reserved,
                    ..
                }))
        );
        let record = revoke_on(&connection, id)?;
        Ok((
            record,
            unrotated.then_some(current.material_generation),
            was_active,
        ))
    }
}

fn revoke_on(
    connection: &Connection,
    id: &CredentialId,
) -> Result<CredentialRecord, LocalCredentialError> {
    let current = load_internal_credential(connection, id, Some(MaterialState::Ready))?;
    if current.public.metadata.status == CredentialStatus::Revoked {
        return Ok(current.public);
    }
    let generation = current
        .public
        .metadata
        .revocation_generation
        .checked_add(1)
        .ok_or(LocalCredentialError::CorruptMetadata)?;
    let changed = connection
        .execute(
            "UPDATE credentials
             SET status = 'revoked', revocation_generation = ?2, updated_at_unix_ms = ?3
             WHERE id = ?1 AND material_state = 'ready'",
            params![
                id.as_str(),
                i64::try_from(generation).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    load_internal_credential(connection, id, Some(MaterialState::Ready)).map(|record| record.public)
}
