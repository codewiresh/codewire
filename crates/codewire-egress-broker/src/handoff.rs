//! The broker's side of the hand-off to the front door (#3999). The header
//! and the socket helpers are [`codewire_egress_policy::handoff`].

use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use codewire_egress_policy::handoff::{
    HANDOFF_ROLE_TAG, HANDOFF_VERSION, HandoffError, HandoffSender, InterceptedStreamHeader,
    stream_pair, valid_environment_id,
};
use codewire_egress_policy::lease::TcpInterception;

use crate::{BrokerAdapterFailure, InterceptHandoff};

/// The broker's side: a `SOCK_STREAM` Unix socket to the front door,
/// inherited from the supervisor. A frame that fails part-way poisons the
/// sender, so every later hand-off is refused (fail closed).
pub struct StreamHandoff {
    sender: Mutex<HandoffSender>,
    environment_id: String,
    next_stream: AtomicU64,
}

impl StreamHandoff {
    pub fn new(socket: OwnedFd, environment_id: String) -> Result<Self, HandoffError> {
        if !valid_environment_id(&environment_id) {
            return Err(HandoffError::Malformed);
        }
        Ok(Self {
            sender: Mutex::new(HandoffSender::new(socket)?),
            environment_id,
            next_stream: AtomicU64::new(1),
        })
    }
}

impl StreamHandoff {
    /// Send the role tag, the first frame the front door reads. The broker
    /// sends it once, right after taking its end, and refuses to start if it
    /// fails.
    pub fn send_role_tag(&self) -> Result<(), HandoffError> {
        self.sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_frame(HANDOFF_ROLE_TAG, &[])
    }
}

impl InterceptHandoff for StreamHandoff {
    fn hand_off(&self, interception: &TcpInterception) -> Result<OwnedFd, BrokerAdapterFailure> {
        // The header carries IPv4 only; the worker drops IPv6 already.
        let IpAddr::V4(destination) = interception.address() else {
            return Err(BrokerAdapterFailure::Malformed);
        };
        let (worker, front_door) = stream_pair().map_err(|_| BrokerAdapterFailure::Unavailable)?;
        let header = InterceptedStreamHeader {
            version: HANDOFF_VERSION,
            hostname: interception.hostname().to_string(),
            port: interception.port(),
            destination_ip: destination,
            stream_id: self.next_stream.fetch_add(1, Ordering::Relaxed),
            environment_id: self.environment_id.clone(),
        };
        // A sender is only ever in a consistent state between calls, so a
        // panic elsewhere leaves it usable.
        self.sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_intercepted_stream(&header, front_door.as_fd())
            .map_err(|error| match error {
                HandoffError::Malformed | HandoffError::Version => BrokerAdapterFailure::Malformed,
                _ => BrokerAdapterFailure::Unavailable,
            })?;
        // The front door holds its own copy now; ours closes here.
        drop(front_door);
        Ok(worker)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream as StdUnixStream;

    use super::*;

    const ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";

    #[test]
    fn the_broker_side_takes_a_stream_socket_and_a_canonical_environment_id() {
        let (stream, _other) = StdUnixStream::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(stream), ENVIRONMENT.into()).is_ok());
        let (stream, _other) = StdUnixStream::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(stream), "env".into()).is_err());
        let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(StreamHandoff::new(OwnedFd::from(datagram), ENVIRONMENT.into()).is_err());
    }
}
