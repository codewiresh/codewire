//! The authenticated network session that carries an environment's packets
//! between its guest and the host's egress worker: the session key, the
//! host hello, guest acknowledgement and host ready handshake, and the
//! framed, MAC-authenticated packets that follow (#4000). A local VM runs it
//! over vsock; a hosted sandbox runs the same session over its stream to
//! cw-egress. Both halves use this one implementation.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod guest;
pub mod hosted;
mod limits;
mod protocol;

pub use limits::{MAX_PACKET_BOUND, MIN_PACKET_BOUND, PacketBound, SessionLimits};
pub use protocol::*;
