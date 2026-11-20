//! The one protected-store write a credential child makes (#5537).
//!
//! A credential child, the broker or the repository executor, opens its
//! authority's store read-only: every `put` and `delete` refuses (#5294). The
//! one exception is the refreshed bundle of a refresh the authority recorded
//! as started. The child stages it itself, in that credential's next material
//! generation, so a rotated refresh token is kept even when the commit's reply
//! is lost; the refresh journal reconciles the write either way.
//!
//! [`RefreshStagingWrite`] is that write. Only a started refresh makes one; it
//! names exactly that credential's next generation and the refresh's
//! execution deadline, it is neither `Clone` nor `Copy`, and staging spends it
//! through [`crate::stage_refreshed_material`], which keeps its empty-entry
//! and deadline checks.
//!
//! A child whose store cannot take that write, a `file` store the broker's
//! Landlock domain only reads, refuses the refresh before Start, so the
//! provider is never asked for a token that could not be kept. #5539 moves
//! staging to the authority, which gives such a root a working refresh.

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedValue,
};

/// A refresh the authority recorded as started: the only source of a
/// [`RefreshStagingWrite`], which spends it.
pub(crate) trait StartedRefreshPermit: Sized {
    /// What the commit still needs once the write is made.
    type Reservation;

    /// The credential's next material generation's entry, the refresh's
    /// execution deadline, and the reservation the commit names.
    fn into_staged(
        self,
    ) -> Result<(ProtectedEntryId, u64, Self::Reservation), crate::LocalCredentialError>;
}

/// The single write of one started refresh's bundle. See the module docs.
///
/// Nothing outside this crate can make one:
///
/// ```compile_fail
/// let write = codewire_local_credentials::RefreshStagingWrite {
///     entry_id: todo!(),
///     execution_deadline_unix_ms: 0,
/// };
/// ```
///
/// It cannot be copied, and staging spends it:
///
/// ```compile_fail
/// fn twice(
///     write: codewire_local_credentials::RefreshStagingWrite,
///     store: &dyn codewire_protected_store::ProtectedStore,
///     material: &codewire_protected_store::ProtectedValue,
/// ) {
///     let _ = write.stage(store, material);
///     let _ = write.stage(store, material);
/// }
/// ```
///
/// ```compile_fail
/// fn copied(write: &codewire_local_credentials::RefreshStagingWrite) {
///     let _: codewire_local_credentials::RefreshStagingWrite = write.clone();
/// }
/// ```
pub struct RefreshStagingWrite {
    entry_id: ProtectedEntryId,
    execution_deadline_unix_ms: u64,
}

impl RefreshStagingWrite {
    /// Spends `started`: one permit makes one write, and the commit keeps
    /// only the reservation.
    pub(crate) fn from_started<P: StartedRefreshPermit>(
        started: P,
    ) -> Result<(Self, P::Reservation), crate::LocalCredentialError> {
        let (entry_id, execution_deadline_unix_ms, reservation) = started.into_staged()?;
        Ok((
            Self {
                entry_id,
                execution_deadline_unix_ms,
            },
            reservation,
        ))
    }

    /// Stage `material` through `store`, the writable store behind a child's
    /// read-only one. An error does not say whether the write took effect.
    pub fn stage<S: ProtectedStore + ?Sized>(
        self,
        store: &S,
        material: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        crate::stage_refreshed_material(
            store,
            &self.entry_id,
            material,
            self.execution_deadline_unix_ms,
        )
    }
}

impl std::fmt::Debug for RefreshStagingWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshStagingWrite")
            .field("entry_id", &self.entry_id)
            .field(
                "execution_deadline_unix_ms",
                &self.execution_deadline_unix_ms,
            )
            .finish()
    }
}

/// A store a credential child stages a started refresh's bundle in.
pub trait RefreshStagingStore: ProtectedStore {
    /// Whether this store can take a started refresh's bundle at all. A child
    /// whose store cannot refuses the refresh before Start.
    fn can_stage_refresh(&self) -> bool;

    /// Spend `write` on `material`, the one write this store accepts.
    fn stage_refresh(
        &self,
        write: RefreshStagingWrite,
        material: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError>;
}

#[cfg(test)]
mod tests;
