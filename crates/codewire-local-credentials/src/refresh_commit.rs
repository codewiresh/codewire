//! Publishing a started refresh: the authority stages the refreshed bundle
//! itself (#5539).
//!
//! A credential child, the broker or the repository executor, opens its store
//! read-only (#5294), so it sends the provider's rotated bundle in Commit and
//! the authority writes it to the credential's next material generation, then
//! promotes it. The entry, the generation and the deadline all come from the
//! authority's own Started record; the request names only the refresh.
//!
//! The store call holds no database lock (#5413): a keyring waiting on an
//! unlock prompt must not stall the authority's other requests. What keeps
//! reconcile away from the credential meanwhile is its refresh ownership,
//! which Begin's and delete's reconcile both respect, and which a channel
//! releases only after its blocking operations, this write included, have
//! returned.

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

use codewire_access::CredentialId;
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedValue,
};
use uuid::Uuid;

use crate::broker_channel::{BrokerLeaseChannelError, StartedBrokerCredentialRefresh};
use crate::control::v1;
use tonic::Status;

use super::{
    CredentialRecord, CredentialRefreshPermit, CredentialRefreshPhase, InternalCredentialRecord,
    JournalOperation, LocalCredentialAuthority, LocalCredentialError, MaterialState,
    ProtectedEntryJournal, fail_oauth_refresh, load_credential_refresh_marker,
    load_internal_credential, load_validated_protected_entry_journal, promote_oauth_refresh,
    stage_refreshed_material, unix_millis, validate_refresh_current,
};

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// Stage `material` as the started refresh's next generation, then promote
    /// it. A retry with the same bytes goes on; different bytes already staged
    /// are refused and left for reconcile. A child sends a Commit again only
    /// when the authority answered `unavailable`, which it does only before
    /// promotion, so a promoted refresh is never asked for twice on a live
    /// channel.
    pub(crate) fn commit_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
        material: &ProtectedValue,
    ) -> Result<(CredentialRecord, u64), LocalCredentialError> {
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        let _settling = self.settling_refreshes.start(permit.credential_id())?;
        let (entry_id, execution_deadline_unix_ms) = {
            let connection = self.connection()?;
            let (_, deadline, journal) = load_started_refresh(&connection, &permit)?;
            (journal.protected_entry_id, deadline)
        };
        stage_once(
            &self.protected_store,
            &entry_id,
            material,
            execution_deadline_unix_ms,
        )?;
        // Promotion calls the store, so it runs on the material connection,
        // which this refresh's ownership permits; the metadata connection
        // was let go above and is never held with it (#5413).
        let connection = self.material_connection()?;
        let (current, _, journal) = load_started_refresh(&connection, &permit)?;
        // Publication is durable bookkeeping, not fresh request authority.
        // The shared broker obtains a new operation lease after this commit.
        // A completed blocking write remains recoverable after its deadline.
        promote_oauth_refresh(
            &crate::MaterialStore::new(&connection, &self.protected_store),
            &current,
            &journal,
        )?;
        let record = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?
        .public;
        drop(connection);
        self.release_credential_refresh(permit.credential_id(), channel_id, refresh_id)?;
        Ok((record, permit.next_material_generation()))
    }

    /// Invalidate an unsuccessful or ambiguous Started attempt. Neither a
    /// provider response nor an opaque transport error is retained. A staged
    /// next generation refuses it: reconcile promotes that entry instead.
    pub(crate) fn fail_environment_credential_refresh(
        &self,
        channel_id: Uuid,
        refresh_id: Uuid,
        request_id: Uuid,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let permit = self.active_refresh_permit(channel_id, refresh_id, request_id)?;
        // A Commit still writing may land after any check of the store, so a
        // Fail and a Commit of one refresh never run together.
        let _settling = self.settling_refreshes.start(permit.credential_id())?;
        let entry_id = {
            let connection = self.connection()?;
            load_started_refresh(&connection, &permit)?
                .2
                .protected_entry_id
        };
        if self.protected_store.get(&entry_id)?.is_some() {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        let connection = self.connection()?;
        let (current, _, _) = load_started_refresh(&connection, &permit)?;
        fail_oauth_refresh(&connection, &current)?;
        let record = load_internal_credential(
            &connection,
            permit.credential_id(),
            Some(MaterialState::Ready),
        )?
        .public;
        drop(connection);
        self.release_credential_refresh(permit.credential_id(), channel_id, refresh_id)?;
        Ok(record)
    }
}

/// The credentials whose refresh a Commit or a Fail is settling now:
/// in-flight state, not a cache. Starting is one insert under one lock, so a
/// Fail and a Commit of the same refresh never both run, and the second is
/// refused as in progress.
#[derive(Default)]
pub(crate) struct Settling(std::sync::Mutex<std::collections::BTreeSet<CredentialId>>);

impl Settling {
    fn start(&self, id: &CredentialId) -> Result<SettlingRefresh<'_>, LocalCredentialError> {
        let mut running = self
            .0
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)?;
        if !running.insert(id.clone()) {
            return Err(LocalCredentialError::CredentialRefreshInProgress);
        }
        Ok(SettlingRefresh {
            settling: self,
            id: id.clone(),
        })
    }
}

/// Ends a credential's settling when dropped, on every exit, a panic
/// included.
struct SettlingRefresh<'a> {
    settling: &'a Settling,
    id: CredentialId,
}

impl Drop for SettlingRefresh<'_> {
    fn drop(&mut self) {
        self.settling
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

/// The started refresh `permit` owns: the current record, the Started
/// deadline, and its rollback-write journal row naming the next entry.
fn load_started_refresh(
    connection: &rusqlite::Connection,
    permit: &CredentialRefreshPermit,
) -> Result<(InternalCredentialRecord, u64, ProtectedEntryJournal), LocalCredentialError> {
    let marker = load_credential_refresh_marker(connection, permit.credential_id())?
        .filter(|marker| &marker.permit == permit)
        .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
    let CredentialRefreshPhase::Started {
        execution_deadline_unix_ms,
    } = marker.phase
    else {
        return Err(LocalCredentialError::StaleCredentialRefresh);
    };
    let current = load_internal_credential(
        connection,
        permit.credential_id(),
        Some(MaterialState::Ready),
    )?;
    validate_refresh_current(&current, &marker)?;
    let journal = load_validated_protected_entry_journal(connection, &current)?
        .filter(|journal| journal.operation == JournalOperation::RollbackWrite)
        .ok_or(LocalCredentialError::StaleCredentialRefresh)?;
    Ok((current, execution_deadline_unix_ms, journal))
}

/// Write `material` into the empty `entry_id` before the deadline, or find it
/// already there from an earlier attempt of this same refresh.
pub(crate) fn stage_once<S: ProtectedStore>(
    store: &S,
    entry_id: &ProtectedEntryId,
    material: &ProtectedValue,
    execution_deadline_unix_ms: u64,
) -> Result<(), LocalCredentialError> {
    match stage_refreshed_material(store, entry_id, material, execution_deadline_unix_ms) {
        Ok(()) => Ok(()),
        Err(ProtectedStoreError::AmbiguousEntry) => match store.get(entry_id)? {
            Some(staged) if staged.expose_secret() == material.expose_secret() => Ok(()),
            Some(_) => Err(LocalCredentialError::ProtectedEntryCollision),
            None => Err(ProtectedStoreError::AmbiguousEntry.into()),
        },
        Err(error) => {
            let before_deadline = unix_millis().is_ok_and(|now| now < execution_deadline_unix_ms);
            if before_deadline {
                Err(error.into())
            } else {
                Err(LocalCredentialError::StaleCredentialRefresh)
            }
        }
    }
}

/// A Commit that did not publish. It hands the started refresh back, so the
/// refresh's failure can still be recorded, unless the authority may still be
/// writing it.
pub struct UnpublishedRefresh {
    pub started: Option<StartedBrokerCredentialRefresh>,
    pub error: BrokerLeaseChannelError,
}

impl UnpublishedRefresh {
    pub(crate) fn new(
        started: StartedBrokerCredentialRefresh,
        error: BrokerLeaseChannelError,
    ) -> Self {
        Self {
            started: Some(started),
            error,
        }
    }

    /// A Commit that ended with `answered` false may still be writing, so it
    /// keeps its started refresh.
    pub(crate) fn ended(
        started: StartedBrokerCredentialRefresh,
        error: BrokerLeaseChannelError,
        answered: bool,
    ) -> Self {
        Self {
            started: answered.then_some(started),
            error,
        }
    }
}

impl std::fmt::Debug for UnpublishedRefresh {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnpublishedRefresh")
            .field("returned", &self.started.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// A Commit's bundle, moved out of the request so only this zeroizing copy
/// remains: empty or over the store's bound is invalid.
pub(crate) fn refresh_commit_material(material: &mut Vec<u8>) -> Result<ProtectedValue, Status> {
    ProtectedValue::new(std::mem::take(material))
        .map_err(|_| Status::invalid_argument("credential refresh commit material is invalid"))
}

/// A Commit whose next generation already holds other bytes is final: the
/// child must not retry it, and reconcile decides that entry.
pub(crate) fn refresh_commit_status(
    error: LocalCredentialError,
    otherwise: fn(LocalCredentialError) -> Status,
) -> Status {
    match error {
        LocalCredentialError::ProtectedEntryCollision => {
            Status::failed_precondition("credential refresh staged other material")
        }
        error => otherwise(error),
    }
}

/// Send `material` as one refresh's Commit through `send`, again while the
/// authority answers `unavailable` (see [`commit_until_answered`]). A failure
/// says whether the authority answered it.
pub(crate) async fn send_commit<F, Fut>(
    execution_deadline_unix_ms: u64,
    refresh_id: Uuid,
    request_id: Uuid,
    material: &ProtectedValue,
    send: F,
) -> Result<v1::BrokerCredentialRefreshCommitResponse, (Status, bool)>
where
    F: Fn(v1::BrokerCredentialRefreshCommitRequest) -> Fut,
    Fut: std::future::Future<
            Output = Result<tonic::Response<v1::BrokerCredentialRefreshCommitResponse>, Status>,
        >,
{
    let (refresh_id, request_id) = (refresh_id.to_string(), request_id.to_string());
    commit_until_answered(execution_deadline_unix_ms, || {
        send(v1::BrokerCredentialRefreshCommitRequest {
            refresh_id: refresh_id.clone(),
            request_id: request_id.clone(),
            material: material.expose_secret().to_vec(),
        })
    })
    .await
    .map(tonic::Response::into_inner)
    .map_err(|status| {
        let answered = commit_was_answered(&status);
        (status, answered)
    })
}

/// Whether a failed Commit was answered by the authority. A timed-out,
/// cancelled or unknown one may still be writing, so its started refresh must
/// not be failed alongside it: its channel ends instead, and drains that write
/// before the refresh is released for reconcile.
pub(crate) fn commit_was_answered(status: &tonic::Status) -> bool {
    !matches!(
        status.code(),
        tonic::Code::Cancelled | tonic::Code::DeadlineExceeded | tonic::Code::Unknown
    )
}

/// The first wait before a Commit is sent again; it doubles up to
/// [`COMMIT_RETRY_MAX`].
const COMMIT_RETRY_INITIAL: std::time::Duration = std::time::Duration::from_millis(250);
const COMMIT_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(4);

/// Send one refresh's Commit, and again while the authority answers
/// `unavailable` and the Started deadline holds: a store that is locked or
/// slow can take the write once the person unlocks it. Any other answer, or
/// the deadline, is final. A closed channel also answers `unavailable`, so it
/// costs at most the rest of the deadline.
pub(crate) async fn commit_until_answered<T, F, Fut>(
    execution_deadline_unix_ms: u64,
    mut send: F,
) -> Result<T, tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, tonic::Status>>,
{
    let mut wait = COMMIT_RETRY_INITIAL;
    loop {
        let status = match send().await {
            Err(status) if status.code() == tonic::Code::Unavailable => status,
            answered => return answered,
        };
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        if !unix_millis().is_ok_and(|now| now.saturating_add(wait_ms) < execution_deadline_unix_ms)
        {
            return Err(status);
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(COMMIT_RETRY_MAX);
    }
}
