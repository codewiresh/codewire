//! The broker's side of the hand-off to the front door (#3999). The header
//! and the socket helpers are [`codewire_egress_policy::handoff`].
//!
//! The broker keeps a copy of each stream's front-door end until the front
//! door acknowledges the stream: one frame back on the hand-off socket whose
//! body is the stream's `stream_id` as eight little-endian bytes, with no
//! descriptor. On macOS, a Unix socket whose only reference left is a
//! descriptor in flight, its sender having closed the last open copy, can be
//! disposed of by the kernel while other descriptors are being passed; the
//! front door then receives a stream already at end of file (measured on
//! macOS 27.2.1, #3999). Linux keeps it. The acknowledgement keeps a process
//! reference until the front door holds its own, on both hosts.
//!
//! The acknowledgements are the only traffic from the front door after its
//! role tag. A reader task on the broker's runtime takes them as they come,
//! so a stream's copy is released at once: a copy held longer would keep the
//! worker from seeing the front door close the stream.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use codewire_egress_policy::handoff::{
    HANDOFF_ROLE_TAG, HANDOFF_VERSION, HandoffError, HandoffReceiver, HandoffSender,
    InterceptedStreamHeader, stream_pair, valid_environment_id,
};
use codewire_egress_policy::lease::TcpInterception;
use tokio::io::Interest;
use tokio::net::UnixStream;

use crate::{BrokerAdapterFailure, InterceptHandoff, MAX_PASSED_FLOWS};

/// An acknowledgement's body: the stream's `stream_id`, little-endian.
pub const HANDOFF_ACK_LEN: usize = 8;

/// The broker's side: a `SOCK_STREAM` Unix socket to the front door,
/// inherited from the supervisor. A frame that fails part-way poisons the
/// sender, and a bad acknowledgement or a closed socket fails the hand-off,
/// so every later hand-off is refused (fail closed).
pub struct StreamHandoff {
    sender: Mutex<HandoffSender>,
    held: Arc<Held>,
    environment_id: String,
    next_stream: AtomicU64,
    reader: tokio::task::JoinHandle<()>,
}

/// The front-door ends the broker still holds, by stream, and whether the
/// hand-off has failed for good.
#[derive(Default)]
struct Held {
    streams: Mutex<HashMap<u64, OwnedFd>>,
    failed: AtomicBool,
}

impl Held {
    fn streams(&self) -> MutexGuard<'_, HashMap<u64, OwnedFd>> {
        self.streams.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Refuse every later hand-off and release every held copy.
    fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.streams().clear();
    }
}

impl StreamHandoff {
    /// Must run within a tokio runtime: the acknowledgement reader is a task
    /// on it, so the broker makes no new thread. Sends the role tag,
    /// [`HANDOFF_ROLE_TAG`], as the socket's first frame; a peer already gone
    /// fails construction with `Closed`.
    pub fn new(socket: OwnedFd, environment_id: String) -> Result<Self, HandoffError> {
        if !valid_environment_id(&environment_id) {
            return Err(HandoffError::Malformed);
        }
        tokio::runtime::Handle::try_current().map_err(|_| HandoffError::Io)?;
        let readable = StdUnixStream::from(socket.try_clone().map_err(|_| HandoffError::Io)?);
        let acknowledgements =
            HandoffReceiver::new(socket.try_clone().map_err(|_| HandoffError::Io)?)?;
        let mut sender = HandoffSender::new(socket)?;
        // The role tag is the first frame the front door reads. Sending it
        // here, once, means no caller can skip or repeat it.
        sender.send_frame(HANDOFF_ROLE_TAG, &[])?;
        // The reader's receives must never block the runtime. Sends already
        // use `MSG_DONTWAIT`, so the shared flag changes nothing for them.
        readable
            .set_nonblocking(true)
            .map_err(|_| HandoffError::Io)?;
        let readable = UnixStream::from_std(readable).map_err(|_| HandoffError::Io)?;
        let held = Arc::new(Held::default());
        let reader = tokio::spawn(read_acknowledgements(
            acknowledgements,
            readable,
            Arc::clone(&held),
        ));
        Ok(Self {
            sender: Mutex::new(sender),
            held,
            environment_id,
            next_stream: AtomicU64::new(1),
            reader,
        })
    }

    /// The streams whose front-door ends the broker still holds.
    pub fn held_streams(&self) -> usize {
        self.held.streams().len()
    }

    /// Whether the hand-off has failed for good: a bad acknowledgement or a
    /// closed socket. Every later hand-off is refused.
    pub fn has_failed(&self) -> bool {
        self.held.failed.load(Ordering::SeqCst)
    }
}

impl Drop for StreamHandoff {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Release each acknowledged stream's copy. An unknown or repeated stream,
/// a body that is not eight bytes, a descriptor, or the socket closing fails
/// the hand-off.
async fn read_acknowledgements(
    mut acknowledgements: HandoffReceiver,
    readable: UnixStream,
    held: Arc<Held>,
) {
    loop {
        if readable.readable().await.is_err() {
            held.fail();
            return;
        }
        // A `WouldBlock` clears the readiness, so the next wait sleeps.
        let received = readable.try_io(Interest::READABLE, || {
            match acknowledgements.recv_frame(HANDOFF_ACK_LEN, 0) {
                Err(HandoffError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
                received => Ok(received),
            }
        });
        let Ok(received) = received else {
            continue;
        };
        let stream = received
            .ok()
            .filter(|(_, descriptors)| descriptors.is_empty())
            .and_then(|(body, _)| <[u8; HANDOFF_ACK_LEN]>::try_from(body.as_slice()).ok())
            .map(u64::from_le_bytes);
        if stream
            .and_then(|stream| held.streams().remove(&stream))
            .is_none()
        {
            held.fail();
            return;
        }
    }
}

impl InterceptHandoff for StreamHandoff {
    fn hand_off(&self, interception: &TcpInterception) -> Result<OwnedFd, BrokerAdapterFailure> {
        // The header carries IPv4 only; the worker drops IPv6 already.
        let IpAddr::V4(destination) = interception.address() else {
            return Err(BrokerAdapterFailure::Malformed);
        };
        let (worker, front_door) = stream_pair().map_err(|_| BrokerAdapterFailure::Unavailable)?;
        let stream_id = self.next_stream.fetch_add(1, Ordering::Relaxed);
        let header = InterceptedStreamHeader {
            version: HANDOFF_VERSION,
            hostname: interception.hostname().to_string(),
            port: interception.port(),
            destination_ip: destination,
            stream_id,
            environment_id: self.environment_id.clone(),
        };
        // Held before it is sent, so its acknowledgement always finds it.
        let copy = front_door
            .try_clone()
            .map_err(|_| BrokerAdapterFailure::Unavailable)?;
        {
            let mut streams = self.held.streams();
            if self.held.failed.load(Ordering::SeqCst) || streams.len() >= MAX_PASSED_FLOWS {
                return Err(BrokerAdapterFailure::Unavailable);
            }
            streams.insert(stream_id, copy);
        }
        // A sender is only ever in a consistent state between calls, so a
        // panic elsewhere leaves it usable.
        let sent = self
            .sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_intercepted_stream(&header, front_door.as_fd());
        // The held copy keeps the stream alive until the front door has it.
        drop(front_door);
        if let Err(error) = sent {
            self.held.streams().remove(&stream_id);
            return Err(match error {
                HandoffError::Malformed | HandoffError::Version => BrokerAdapterFailure::Malformed,
                _ => BrokerAdapterFailure::Unavailable,
            });
        }
        Ok(worker)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream as StdUnixStream;

    use super::*;

    const ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";

    #[tokio::test]
    async fn the_broker_side_takes_a_stream_socket_and_a_canonical_environment_id() {
        let (stream, _other) = StdUnixStream::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(stream), ENVIRONMENT.into()).is_ok());
        let (stream, _other) = StdUnixStream::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(stream), "env".into()).is_err());
        let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(datagram), ENVIRONMENT.into()).is_err());
    }

    /// Construction sends the role tag exactly once, as the first frame, so
    /// the front door's `expect_role_tag` passes and nothing repeats it.
    #[tokio::test]
    async fn construction_sends_the_role_tag_once_first() {
        let (broker_end, front_door_end) = codewire_egress_policy::handoff::stream_pair().unwrap();
        let _handoff = StreamHandoff::new(broker_end, ENVIRONMENT.into()).unwrap();
        let mut front_door = HandoffReceiver::new(front_door_end).unwrap();
        front_door
            .expect_role_tag(std::time::Duration::from_secs(2))
            .unwrap();
        rustix::io::ioctl_fionbio(&front_door, true).unwrap();
        assert_eq!(
            front_door
                .recv_frame(HANDOFF_ROLE_TAG.len(), 0)
                .unwrap_err(),
            HandoffError::WouldBlock
        );
    }

    /// #3999: a front door that poisons its receiver shuts the socket down,
    /// and the broker's acknowledgement reader reads end of file at once,
    /// though the front door keeps its descriptor open. On macOS that end of
    /// file is the only signal a plain send would not give.
    #[tokio::test]
    async fn a_front_door_that_poisons_fails_the_hand_off_at_once() {
        let (broker_end, front_door_end) = codewire_egress_policy::handoff::stream_pair().unwrap();
        let handoff = StreamHandoff::new(broker_end, ENVIRONMENT.into()).unwrap();
        let mut front_door = HandoffReceiver::new(front_door_end).unwrap();
        front_door
            .expect_role_tag(std::time::Duration::from_secs(2))
            .unwrap();
        // A second wait finds no role tag, and poisons.
        assert!(
            front_door
                .expect_role_tag(std::time::Duration::from_millis(50))
                .is_err()
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !handoff.has_failed() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the broker never read the front door's shutdown");
        drop(front_door);
    }

    #[tokio::test]
    async fn a_front_door_already_gone_fails_construction() {
        let (broker_end, front_door_end) = codewire_egress_policy::handoff::stream_pair().unwrap();
        drop(front_door_end);
        assert_eq!(
            StreamHandoff::new(broker_end, ENVIRONMENT.into()).err(),
            Some(HandoffError::Closed)
        );
    }

    #[test]
    fn the_broker_side_needs_a_runtime_for_its_acknowledgement_reader() {
        let (stream, _other) = StdUnixStream::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(stream), ENVIRONMENT.into()).is_err());
    }
}
