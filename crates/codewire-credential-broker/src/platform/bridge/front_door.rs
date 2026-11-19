//! Front-door streams joining an admitted epoch (codewire#4001, #4909).
//!
//! An admitted `CredentialBridge` epoch gets a random handle, returned only
//! in its response headers. A `FrontDoorBridge` stream joins that epoch by
//! presenting the same relay and workspace authorization and then the
//! handle, which is looked up only among the live epochs of the binding the
//! authorization names. The handle grants nothing alone, is compared in
//! constant time, lives only as long as its epoch, and is never logged: it
//! has no `Debug`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES, CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
};
use rand::RngCore as _;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::time::Instant;
use tonic::Status;
use tonic::metadata::{BinaryMetadataValue, MetadataMap};
use uuid::Uuid;

use super::RelayTransport;
use crate::AdmittedCredentialBridge;

/// One epoch's front-door handle.
pub(super) struct EpochHandle([u8; CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES]);

impl EpochHandle {
    fn generate() -> Result<Self, Status> {
        let mut bytes = [0_u8; CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| Status::unavailable("credential broker unavailable"))?;
        Ok(Self(bytes))
    }

    /// The one handle a `FrontDoorBridge` caller presents, exactly
    /// [`CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES`] long; anything else is none.
    pub(super) fn presented(metadata: &MetadataMap) -> Option<Self> {
        let mut values = metadata
            .get_all_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER)
            .iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return None;
        };
        let bytes = value.to_bytes().ok()?;
        Some(Self(bytes.as_ref().try_into().ok()?))
    }

    /// The handle as the admitted epoch's response header value.
    pub(super) fn header_value(&self) -> BinaryMetadataValue {
        BinaryMetadataValue::from_bytes(&self.0)
    }

    /// The handle's bytes, for a delegation's admission answer only.
    pub(super) fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Constant time: every byte is compared whatever the first difference.
    fn matches(&self, other: &Self) -> bool {
        let difference = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |acc, (a, b)| std::hint::black_box(acc | (a ^ b)));
        difference == 0
    }
}

/// The one refusal for any handle that joins nothing: missing, repeated, of
/// another length, unknown, ended or another scope's. A caller cannot tell
/// which.
pub(super) fn handle_refused() -> Status {
    Status::permission_denied("credential bridge denied")
}

/// What a joined front-door stream needs of its epoch.
#[derive(Clone, Copy)]
pub(super) struct EpochBounds {
    pub(super) expires_at_unix: u64,
    pub(super) deadline: Instant,
}

/// The live epochs a front-door stream may join.
/// Whose epochs a front-door stream may join: a hosted binding's, named by
/// the workspace authorization, or one owner's delegations, named by the
/// owner's OAuth identity (#4909). A claim searches only its own scope, so
/// another scope's valid handle is refused like any unknown one.
#[derive(Clone, PartialEq, Eq)]
pub enum FrontDoorScope {
    Binding {
        environment_id: Uuid,
        generation: u64,
    },
    Owner(String),
}

#[derive(Default)]
pub(super) struct Registry {
    slots: Mutex<Vec<Slot>>,
}

struct Slot {
    scope: FrontDoorScope,
    environment_id: Uuid,
    generation: u64,
    handle: EpochHandle,
    bounds: EpochBounds,
    joins: mpsc::Sender<AdmittedCredentialBridge<RelayTransport>>,
    occupied: Arc<AtomicBool>,
}

/// An epoch's place in the registry, removed when this is dropped: when the
/// epoch's worker ends, however it ends.
pub(super) struct Registration {
    registry: Arc<Registry>,
    handle: EpochHandle,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.registry.slots.lock() {
            slots.retain(|slot| !slot.handle.matches(&self.handle));
        }
    }
}

/// A claimed epoch: where the joining stream goes, and the guard that keeps
/// the epoch claimed while that stream lives.
pub(super) struct Claim {
    pub(super) joins: mpsc::Sender<AdmittedCredentialBridge<RelayTransport>>,
    pub(super) bounds: EpochBounds,
    pub(super) guard: Occupied,
    /// The epoch's own environment: a join never names one.
    pub(super) environment_id: Uuid,
    pub(super) generation: u64,
}

/// Holds an epoch's one front-door place, and the stream's admission permit,
/// until the joined stream's transport is dropped.
pub(crate) struct Occupied {
    flag: Arc<AtomicBool>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Occupied {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

impl Registry {
    /// Register an admitted epoch in `scope`; returns its handle, and the
    /// registration that removes it on drop.
    pub(super) fn register(
        self: &Arc<Self>,
        scope: FrontDoorScope,
        environment_id: Uuid,
        generation: u64,
        bounds: EpochBounds,
        joins: mpsc::Sender<AdmittedCredentialBridge<RelayTransport>>,
    ) -> Result<(EpochHandle, Registration), Status> {
        let handle = EpochHandle::generate()?;
        let returned = EpochHandle(handle.0);
        let registration = Registration {
            registry: Arc::clone(self),
            handle: EpochHandle(handle.0),
        };
        self.slots
            .lock()
            .map_err(|_| Status::unavailable("credential broker unavailable"))?
            .push(Slot {
                scope,
                environment_id,
                generation,
                handle,
                bounds,
                joins,
                occupied: Arc::new(AtomicBool::new(false)),
            });
        Ok((returned, registration))
    }

    /// Claim the epoch in `scope` whose handle is `presented`. Only that
    /// scope's epochs are searched, so another scope's valid handle is
    /// refused like any unknown one. A claimed epoch refuses a second claim
    /// until the first stream's guard is dropped.
    pub(super) fn claim(
        &self,
        scope: &FrontDoorScope,
        presented: &EpochHandle,
        permit: OwnedSemaphorePermit,
    ) -> Result<Claim, Status> {
        let slots = self
            .slots
            .lock()
            .map_err(|_| Status::unavailable("credential broker unavailable"))?;
        let slot = slots
            .iter()
            .filter(|slot| slot.scope == *scope)
            .fold(None, |found, slot| {
                // Every candidate is compared, so the time taken does not
                // depend on which one matches.
                let matches = slot.handle.matches(presented);
                found.or(matches.then_some(slot))
            })
            .ok_or_else(handle_refused)?;
        if slot
            .occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Status::already_exists(
                "this epoch already serves a front-door stream",
            ));
        }
        Ok(Claim {
            joins: slot.joins.clone(),
            bounds: slot.bounds,
            guard: Occupied {
                flag: Arc::clone(&slot.occupied),
                _permit: permit,
            },
            environment_id: slot.environment_id,
            generation: slot.generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_match_only_themselves_and_are_never_repeated() {
        let one = EpochHandle::generate().unwrap();
        let two = EpochHandle::generate().unwrap();
        assert!(one.matches(&EpochHandle(one.0)));
        assert!(!one.matches(&two));
        let mut near = EpochHandle(one.0);
        near.0[CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES - 1] ^= 1;
        assert!(
            !one.matches(&near),
            "a difference in the last byte is caught"
        );
    }

    #[test]
    fn a_presented_handle_must_be_one_value_of_exactly_its_length() {
        let handle = EpochHandle::generate().unwrap();
        let mut metadata = MetadataMap::new();
        assert!(EpochHandle::presented(&metadata).is_none());
        metadata.insert_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER, handle.header_value());
        assert!(EpochHandle::presented(&metadata).unwrap().matches(&handle));
        metadata.append_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER, handle.header_value());
        assert!(
            EpochHandle::presented(&metadata).is_none(),
            "two values are none"
        );
        let mut short = MetadataMap::new();
        short.insert_bin(
            CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
            BinaryMetadataValue::from_bytes(&handle.0[..16]),
        );
        assert!(
            EpochHandle::presented(&short).is_none(),
            "a short value is none"
        );
    }
}
