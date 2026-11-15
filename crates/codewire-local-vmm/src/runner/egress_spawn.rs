//! The egress broker's inherited sockets (#2638) and its hand-off to the
//! environment's front door (#3999).

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;

use codewire_egress_policy::intercept::InterceptSet;

use super::{
    EgressBrokerProcess, INHERITED_SOURCE_FLOOR, RunnerError, duplicate_inherited_descriptor,
};
use crate::egress_broker::EGRESS_BROKER_HANDOFF_FD;

const _: () = assert!(EGRESS_BROKER_HANDOFF_FD < INHERITED_SOURCE_FLOOR);

/// A socket pair for the broker: the runner's end, non-blocking, and the
/// broker's end duplicated above the inherited-descriptor floor.
pub(super) struct InheritedPair {
    pub(super) parent: tokio::net::UnixStream,
    pub(super) inherited: OwnedFd,
}

pub(super) fn inherited_pair() -> Result<InheritedPair, RunnerError> {
    let (parent, child) = StdUnixStream::pair().map_err(|_| RunnerError::EgressBrokerSpawn)?;
    parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::EgressBrokerSpawn)?;
    let parent =
        tokio::net::UnixStream::from_std(parent).map_err(|_| RunnerError::EgressBrokerSpawn)?;
    let inherited = duplicate_inherited_descriptor(child.as_raw_fd())
        .map_err(|_| RunnerError::EgressBrokerSpawn)?;
    Ok(InheritedPair { parent, inherited })
}

/// The hand-off socket: a Unix stream pair, the same on Linux and macOS, made
/// before the broker starts. The broker inherits one end at
/// [`EGRESS_BROKER_HANDOFF_FD`]; the front door gets the other.
pub(super) struct BrokerHandoff {
    inherited: OwnedFd,
    front_door: OwnedFd,
}

impl BrokerHandoff {
    /// None for an empty set: interception is off, and the broker starts
    /// exactly as it would without it.
    pub(super) fn prepare(intercepts: &InterceptSet) -> Result<Option<Self>, RunnerError> {
        if intercepts.is_empty() {
            return Ok(None);
        }
        let (broker, front_door) = codewire_egress_policy::handoff::stream_pair()
            .map_err(|_| RunnerError::EgressBrokerSpawn)?;
        let inherited = duplicate_inherited_descriptor(broker.as_raw_fd())
            .map_err(|_| RunnerError::EgressBrokerSpawn)?;
        Ok(Some(Self {
            inherited,
            front_door,
        }))
    }

    /// The broker's end and where the child receives it.
    pub(super) fn inherited(&self) -> (RawFd, RawFd) {
        (self.inherited.as_raw_fd(), EGRESS_BROKER_HANDOFF_FD)
    }

    /// After the spawn: close the runner's copy of the broker's end and keep
    /// only the front door's.
    pub(super) fn into_front_door(self) -> OwnedFd {
        self.front_door
    }
}

/// The bindings the broker reads before it is ready, or none when
/// interception is off.
pub(super) fn intercept_frame(intercepts: &InterceptSet) -> Result<Option<Vec<u8>>, RunnerError> {
    if intercepts.is_empty() {
        return Ok(None);
    }
    crate::broker_control::encode_intercept_frame(intercepts)
        .map(Some)
        .map_err(|_| RunnerError::EgressBrokerBootstrap)
}

impl EgressBrokerProcess {
    /// Take the front door's end of the hand-off socket. Once taken the
    /// runner holds no copy, so when the front door closes it the broker's
    /// sends fail at once; until then every intercepted dial is handed to it.
    #[expect(
        dead_code,
        reason = "the front-door wiring takes it (#3999, the front-door PR)"
    )]
    pub(super) fn take_front_door_handoff(&mut self) -> Option<OwnedFd> {
        self.front_door_handoff.take()
    }
}

#[cfg(test)]
mod tests {
    use codewire_egress_policy::intercept::InterceptBinding;

    use super::*;

    /// An empty set is interception off: no hand-off socket, no bindings
    /// frame, so the broker starts exactly as it does without interception.
    #[test]
    fn an_empty_set_makes_no_hand_off_and_sends_no_bindings() {
        let empty = InterceptSet::default();
        assert!(BrokerHandoff::prepare(&empty).unwrap().is_none());
        assert!(intercept_frame(&empty).unwrap().is_none());
    }

    #[test]
    fn a_bound_set_makes_a_stream_pair_and_a_bindings_frame() {
        let set =
            InterceptSet::new([InterceptBinding::new("api.anthropic.com", 443).unwrap()]).unwrap();
        let handoff = BrokerHandoff::prepare(&set).unwrap().unwrap();
        let (source, target) = handoff.inherited();
        assert!(source >= INHERITED_SOURCE_FLOOR);
        assert_eq!(target, EGRESS_BROKER_HANDOFF_FD);
        let front_door = handoff.into_front_door();
        assert_eq!(
            rustix::net::sockopt::socket_type(&front_door).unwrap(),
            rustix::net::SocketType::STREAM
        );
        assert!(intercept_frame(&set).unwrap().is_some());
    }
}
