//! The hand-off of an intercepted connection to the environment's front door
//! (#3999).
//!
//! The guest's TCP connection ends inside the network worker's user-space
//! stack, so there is no guest socket to pass. On an intercept decision the
//! broker makes a Unix stream pair instead: one end returns to the worker,
//! which splices the guest's connection onto it, and the other goes to the
//! front door with a [`InterceptedStreamHeader`] header, one descriptor per message,
//! over a `SOCK_STREAM` socket the supervisor made before either process
//! started, one length-prefixed frame per connection ([`HandoffSender`],
//! [`HandoffReceiver`]); the same framing works on Linux and macOS. The
//! broker opens no network connection for it and the front door
//! never answers on that socket: a failure is the front door closing its end.
//!
//! The first frame on the socket is a role tag, [`HANDOFF_ROLE_TAG`]: a body
//! of exactly `b"H"` with no descriptors, sent by the broker as soon as it
//! takes its end and before any intercepted stream. The front door reads it
//! first, waits at most 2 s for it, and refuses the socket without it. (The
//! credential socket is told apart by a raw `C` byte on the front door's
//! side.)
//!
//! The header is a fixed little-endian layout, not protobuf, so the confined
//! broker needs no generated code. It lives here, not in the broker, so the
//! front door can use it without depending on the confined broker:
//!
//! | bytes  | field                                         |
//! |--------|-----------------------------------------------|
//! | 0–1    | version, 1                                    |
//! | 2–3    | hostname length N (1..=253)                   |
//! | 4–5    | port (non-zero)                               |
//! | 6–9    | the IPv4 address the guest dialled            |
//! | 10–17  | stream id, unique per broker run              |
//! | 18–19  | environment id length M (36: a canonical UUID) |
//! | 20..   | hostname (N bytes, lowercase ASCII), then the environment id (M bytes) |
//!
//! The descriptor is a byte stream, not necessarily TCP: a receiver never
//! reads its peer address. It checks the binding against its own interception
//! set, never trusting the broker for it.

mod frame;
mod header;

pub use frame::{
    ENOBUFS_WHOLE_FRAME_LEN, FRAME_MAX_LEN, HandoffReceiver, HandoffSender,
    is_connected_unix_stream, stream_pair,
};
pub use header::{InterceptedStreamHeader, valid_environment_id};

use thiserror::Error;

/// The body of the first frame on a hand-off socket.
pub const HANDOFF_ROLE_TAG: &[u8] = b"H";
pub const HANDOFF_VERSION: u16 = 1;
pub const HANDOFF_FIXED_LEN: usize = 20;
pub const HANDOFF_MAX_HOSTNAME_LEN: usize = 253;
/// An environment id is a canonical UUID.
pub const HANDOFF_ENVIRONMENT_ID_LEN: usize = 36;
pub const HANDOFF_MAX_LEN: usize =
    HANDOFF_FIXED_LEN + HANDOFF_MAX_HOSTNAME_LEN + HANDOFF_ENVIRONMENT_ID_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandoffError {
    #[error("the hand-off header is malformed")]
    Malformed,
    #[error("the hand-off header has an unknown version")]
    Version,
    #[error("a hand-off frame must carry exactly the descriptors it allows")]
    Descriptors,
    #[error("the hand-off socket closed")]
    Closed,
    /// A non-blocking socket has no complete frame yet; wait for readability.
    /// A receiver keeps what it has read and resumes on the next call.
    #[error("the hand-off socket has no complete frame yet")]
    WouldBlock,
    /// An earlier failure left the stream out of step; it is unusable.
    #[error("the hand-off socket is unusable after an earlier failure")]
    Poisoned,
    #[error("the hand-off socket failed")]
    Io,
}

#[cfg(test)]
mod tests;
