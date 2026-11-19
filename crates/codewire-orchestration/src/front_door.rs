//! Hosted front-door sessions through the credential relay (#4001).
//!
//! cw-egress's TLS front door reaches the credential broker only through the
//! relay epoch already running for its Pod's binding. Each admitted epoch
//! registers here a way to ask it to open one `FrontDoorBridge` stream; the
//! relay token, the daemon's workspace authorization and the epoch's handle
//! never leave the epoch. `EgressService.FrontDoorSession` finds the epoch by
//! the Pod's live binding and asks. The newest admitted epoch of a binding is
//! the current one, so a session opened during a renewal joins the successor
//! and never the epoch that is draining.
//!
//! Frames cross unparsed, each exactly one front-door.v1 frame as on the
//! local socket: a four-byte big-endian length, then that many protobuf
//! bytes, at most [`CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES`]. Only that
//! length is read.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use futures::stream::BoxStream;
use tokio::sync::{mpsc, oneshot};
use tonic::Status;
use uuid::Uuid;

const LENGTH_BYTES: usize = 4;

/// The binding an epoch relays, exactly as the relay was started for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BindingKey {
    pub environment_id: Uuid,
    pub pod_uid: String,
    pub generation: u64,
}

/// A front-door session asking an epoch to open its broker stream.
pub struct Join {
    /// The guest's frames, each one framed message.
    pub frames: BoxStream<'static, Result<Vec<u8>, Status>>,
    pub reply: oneshot::Sender<Result<Joined, Status>>,
}

/// A joined broker stream: the host's frames, starting with the Open the
/// relay writes from the broker's capabilities. It ends with its epoch.
pub struct Joined {
    pub frames: BoxStream<'static, Result<Vec<u8>, Status>>,
    /// Ends the session when dropped, so it never outlives the stream
    /// cw-egress reads.
    pub session: tokio_util::sync::DropGuard,
}

/// The live epochs a front-door session may join, one current per binding.
#[derive(Default)]
pub struct FrontDoorEpochs {
    slots: Mutex<HashMap<BindingKey, Slot>>,
    next: AtomicU64,
}

struct Slot {
    id: u64,
    joins: mpsc::Sender<Join>,
}

/// An epoch's place, removed on drop unless a successor has replaced it.
pub struct Registration {
    epochs: Arc<FrontDoorEpochs>,
    key: BindingKey,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut slots = self
            .epochs
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slots.get(&self.key).is_some_and(|slot| slot.id == self.id) {
            slots.remove(&self.key);
        }
    }
}

impl FrontDoorEpochs {
    /// Make `joins` the binding's current epoch, replacing any older one.
    pub fn register(self: &Arc<Self>, key: BindingKey, joins: mpsc::Sender<Join>) -> Registration {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone(), Slot { id, joins });
        Registration {
            epochs: Arc::clone(self),
            key,
            id,
        }
    }

    /// The binding's current epoch, if one is admitted on this process.
    pub fn current(&self, key: &BindingKey) -> Option<mpsc::Sender<Join>> {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map(|slot| slot.joins.clone())
    }
}

/// The message inside one framed front-door frame: refused unless the length
/// is not zero, within the bridge's maximum, and exactly the bytes that
/// follow it.
pub fn frame_message(frame: &[u8]) -> Option<&[u8]> {
    let (prefix, message) = frame.split_first_chunk::<LENGTH_BYTES>()?;
    let length = usize::try_from(u32::from_be_bytes(*prefix)).ok()?;
    (length != 0 && length <= CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES && length == message.len())
        .then_some(message)
}

/// `message` as one framed front-door frame.
pub fn framed(message: &[u8]) -> Option<Vec<u8>> {
    if message.is_empty() || message.len() > CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES {
        return None;
    }
    let prefix = u32::try_from(message.len()).ok()?;
    let mut frame = Vec::with_capacity(LENGTH_BYTES + message.len());
    frame.extend_from_slice(&prefix.to_be_bytes());
    frame.extend_from_slice(message);
    Some(frame)
}

#[cfg(test)]
mod tests;
