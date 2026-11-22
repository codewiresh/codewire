//! Closing a credential's refresh journal, and the wait after a refresh the
//! provider rate-limited (#4975; docs/dev/SECRETS-AND-CREDENTIALS.md, "A
//! refresh the provider rate-limited").
//!
//! The wait is its own metadata record, bound to the credential's
//! generations, because a refresh marker always has its rollback-write
//! journal row beside it. A refresh begun after the wait marks the record, so
//! that refresh cannot be rate-limited again and any failure of it is
//! terminal. An authority that predates the record never reads its key.

use std::ops::RangeInclusive;

use codewire_access::CredentialId;
use codewire_protected_store::ProtectedStore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CredentialRefreshPhase, InternalCredentialRecord, JournalOperation, LocalCredentialAuthority,
    LocalCredentialError, MaterialState, MaterialStore, credential_refresh_marker_key,
    database_error, load_credential_refresh_marker, load_internal_credential,
    load_validated_protected_entry_journal, unix_millis, validate_refresh_current,
};

/// The bounds of a rate-limit wait, whatever the provider's `Retry-After`.
pub const RATE_LIMIT_WAIT_SECONDS: RangeInclusive<u64> = 60..=600;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RefreshWait {
    material_generation: u64,
    revocation_generation: u64,
    until_unix_ms: u64,
    retry_began: bool,
}

impl RefreshWait {
    fn of(&self, credential: &InternalCredentialRecord) -> bool {
        self.material_generation == credential.material_generation
            && self.revocation_generation == credential.public.metadata.revocation_generation
    }
}

fn wait_key(credential_id: &CredentialId) -> String {
    format!("credential_refresh_wait/{}", credential_id.as_str())
}

fn load_wait(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<Option<RefreshWait>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT value FROM authority_metadata WHERE key = ?1",
            [wait_key(credential_id)],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|value| {
            serde_json::from_str(&value).map_err(|_| LocalCredentialError::CorruptMetadata)
        })
        .transpose()
}

fn store_wait(
    connection: &Connection,
    credential_id: &CredentialId,
    wait: &RefreshWait,
) -> Result<(), LocalCredentialError> {
    connection
        .execute(
            "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![
                wait_key(credential_id),
                serde_json::to_string(wait).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

/// Before a refresh of `credential` begins: refused while its wait runs; the
/// first refresh after the wait marks it. A wait from another generation (a
/// published refresh, a failure, a reconnect) no longer applies and is
/// forgotten.
pub(crate) fn admit_after_wait(
    connection: &Connection,
    credential: &InternalCredentialRecord,
) -> Result<(), LocalCredentialError> {
    let id = &credential.public.metadata.id;
    let Some(mut wait) = load_wait(connection, id)? else {
        return Ok(());
    };
    if !wait.of(credential) {
        connection
            .execute(
                "DELETE FROM authority_metadata WHERE key = ?1",
                [wait_key(id)],
            )
            .map_err(database_error)?;
        return Ok(());
    }
    let left_ms = wait.until_unix_ms.saturating_sub(unix_millis()?);
    if left_ms > 0 {
        return Err(LocalCredentialError::CredentialRefreshRateLimited {
            retry_after_seconds: left_ms.div_ceil(1_000),
        });
    }
    if !wait.retry_began {
        wait.retry_began = true;
        store_wait(connection, id, &wait)?;
    }
    Ok(())
}

pub(crate) fn delete_credential_refresh_journal(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let transaction = crate::immediate(connection)?;
    delete_journal_in(&transaction, credential_id)?;
    transaction.commit().map_err(database_error)
}

fn delete_journal_in(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let journal_changed = connection
        .execute(
            "DELETE FROM protected_entry_journal WHERE credential_id = ?1",
            [credential_id.as_str()],
        )
        .map_err(database_error)?;
    let marker_changed = connection
        .execute(
            "DELETE FROM authority_metadata WHERE key = ?1",
            [credential_refresh_marker_key(credential_id)],
        )
        .map_err(database_error)?;
    if journal_changed != 1 || marker_changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Close the exact started refresh as rate-limited for `wait_seconds`,
    /// held to [`RATE_LIMIT_WAIT_SECONDS`], after the provider answered 429
    /// with its whole response read. The credential and its material stay as
    /// they were. A refresh begun after
    /// a wait is refused as stale, and the broker then fails it, which is
    /// terminal.
    pub(crate) fn rate_limit_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
        wait_seconds: u64,
    ) -> Result<(), LocalCredentialError> {
        let wait_seconds = wait_seconds.clamp(
            *RATE_LIMIT_WAIT_SECONDS.start(),
            *RATE_LIMIT_WAIT_SECONDS.end(),
        );
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        let id = permit.credential_id();
        // The material connection, as an abort's: the store check below never
        // waits while the metadata connection is held (#5413).
        let connection = self.material_connection()?;
        let marker = load_credential_refresh_marker(&connection, id)?
            .filter(|marker| {
                marker.permit == permit
                    && matches!(marker.phase, CredentialRefreshPhase::Started { .. })
            })
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        validate_refresh_current(&current, &marker)?;
        let journal = load_validated_protected_entry_journal(&connection, &current)?
            .filter(|journal| journal.operation == JournalOperation::RollbackWrite)
            .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
        if MaterialStore::new(&connection, &self.protected_store)
            .get(&journal.protected_entry_id)?
            .is_some()
        {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        if load_wait(&connection, id)?.is_some_and(|wait| wait.of(&current) && wait.retry_began) {
            return Err(LocalCredentialError::StaleCredentialRefresh);
        }
        let until_unix_ms = unix_millis()?
            .checked_add(wait_seconds * 1_000)
            .ok_or(LocalCredentialError::InvalidTime)?;
        let transaction = crate::immediate(&connection)?;
        delete_journal_in(&transaction, id)?;
        store_wait(
            &transaction,
            id,
            &RefreshWait {
                material_generation: current.material_generation,
                revocation_generation: current.public.metadata.revocation_generation,
                until_unix_ms,
                retry_began: false,
            },
        )?;
        transaction.commit().map_err(database_error)?;
        drop(connection);
        self.release_credential_refresh(id, channel_id, refresh_id)
    }
}
