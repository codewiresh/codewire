//! The framing of the hand-off socket: a two-byte little-endian length, then
//! the body, written by one `sendmsg` that carries the frame's descriptors as
//! `SCM_RIGHTS`. Both kernels attach the descriptors to the first byte and
//! never merge ancillary data across `sendmsg` calls, so a receiver that
//! takes descriptors only with a frame's first byte and never reads past the
//! frame's end keeps descriptors and frames in step, even when the kernel
//! joins frames on the stream (macOS may).
//!
//! Linux sends with `MSG_NOSIGNAL` and receives with `MSG_CMSG_CLOEXEC`.
//! macOS has neither: the sender sets `SO_NOSIGPIPE` on its socket, and the
//! receiver marks each received descriptor close-on-exec at once.

use std::io::{IoSlice, IoSliceMut};
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg,
};

use std::time::{Duration, Instant};

use super::{HANDOFF_MAX_LEN, HANDOFF_ROLE_TAG, HandoffError, InterceptedStreamHeader};

/// The longest frame body the two-byte length can carry.
pub const FRAME_MAX_LEN: usize = u16::MAX as usize;

/// The most descriptors one frame may carry.
const FRAME_MAX_DESCRIPTORS: usize = 4;

#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::DONTWAIT.union(SendFlags::NOSIGNAL);
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::DONTWAIT;
#[cfg(target_os = "linux")]
const RECEIVE_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECEIVE_FLAGS: RecvFlags = RecvFlags::empty();

/// The writing end of a hand-off socket. It never blocks.
///
/// Which errors poison it:
/// - `EINTR` sent nothing and is retried.
/// - `EAGAIN` and `ETOOMANYREFS` (too many descriptors in flight) sent
///   nothing: the send fails with `WouldBlock`, and the sender stays usable.
/// - `ENOBUFS` is how macOS reports a full Unix socket buffer, but it may
///   have queued part of a large frame first. For a frame under
///   [`ENOBUFS_WHOLE_FRAME_LEN`] bytes, which fits one socket buffer and so
///   goes in whole or not at all, it is `WouldBlock`; for a larger one it
///   poisons.
/// - A closed peer is `Closed`: `EPIPE` or `ECONNRESET`, and on macOS
///   `EINVAL` for a frame that carries descriptors. macOS refuses descriptors
///   to a peer that has shut its receiving side down with `EINVAL`, and
///   still takes plain bytes (measured on macOS 27.2.1, #3999).
/// - A frame that went out only in part, a closed peer, or any other error
///   poisons it: the stream may be out of step, so it shuts down its writing
///   side (the front door reads end of file) and every later send fails with
///   `Poisoned`.
pub struct HandoffSender {
    socket: OwnedFd,
    state: SenderState,
}

/// A frame shorter than this goes out whole or not at all, so `ENOBUFS` on it
/// sent nothing.
pub const ENOBUFS_WHOLE_FRAME_LEN: usize = 2_048;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SenderState {
    Ready,
    /// The peer was already gone when the sender was made: the first send
    /// reports `Closed` without a syscall.
    #[cfg_attr(
        target_os = "linux",
        expect(dead_code, reason = "only macOS makes a sender already closed")
    )]
    Closed,
    Poisoned,
}

impl HandoffSender {
    /// Takes an `AF_UNIX` `SOCK_STREAM` socket. It never asks for the peer
    /// (macOS reports a closed one as not connected): a closed peer shows at
    /// the first send or receive.
    pub fn new(socket: OwnedFd) -> Result<Self, HandoffError> {
        if !is_unix_stream(socket.as_fd()) {
            return Err(HandoffError::Io);
        }
        // macOS has no MSG_NOSIGNAL, so without SO_NOSIGPIPE a send could
        // raise SIGPIPE. It refuses the option with EINVAL on a stream whose
        // peer is gone: that sender never calls sendmsg, and its first send
        // is `Closed`.
        #[cfg(not(target_os = "linux"))]
        let state = match rustix::net::sockopt::set_socket_nosigpipe(&socket, true) {
            Ok(()) => SenderState::Ready,
            Err(rustix::io::Errno::INVAL) => SenderState::Closed,
            Err(_) => return Err(HandoffError::Io),
        };
        #[cfg(target_os = "linux")]
        let state = SenderState::Ready;
        Ok(Self { socket, state })
    }

    /// Sends one frame carrying `descriptors` (at most four).
    pub fn send_frame(
        &mut self,
        body: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), HandoffError> {
        match self.state {
            SenderState::Ready => {}
            SenderState::Poisoned => return Err(HandoffError::Poisoned),
            SenderState::Closed => {
                self.state = SenderState::Poisoned;
                return Err(HandoffError::Closed);
            }
        }
        let length = u16::try_from(body.len()).map_err(|_| HandoffError::Malformed)?;
        if descriptors.len() > FRAME_MAX_DESCRIPTORS {
            return Err(HandoffError::Descriptors);
        }
        let prefix = length.to_le_bytes();
        let vectors = [IoSlice::new(&prefix), IoSlice::new(body)];
        let mut space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FRAME_MAX_DESCRIPTORS))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors))
        {
            return Err(HandoffError::Descriptors);
        }
        let total = prefix.len() + body.len();
        let result = loop {
            match sendmsg(&self.socket, &vectors, &mut ancillary, SEND_FLAGS) {
                Ok(sent) if sent == total => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) if is_would_block(error) || error == rustix::io::Errno::TOOMANYREFS => {
                    return Err(HandoffError::WouldBlock);
                }
                Err(rustix::io::Errno::NOBUFS) if total < ENOBUFS_WHOLE_FRAME_LEN => {
                    return Err(HandoffError::WouldBlock);
                }
                Ok(_) => break HandoffError::Io,
                Err(rustix::io::Errno::PIPE | rustix::io::Errno::CONNRESET) => {
                    break HandoffError::Closed;
                }
                #[cfg(target_os = "macos")]
                Err(rustix::io::Errno::INVAL) if !descriptors.is_empty() => {
                    break HandoffError::Closed;
                }
                Err(_) => break HandoffError::Io,
            }
        };
        self.state = SenderState::Poisoned;
        // Best effort: a peer already gone has nothing left to tell.
        let _ = rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Write);
        Err(result)
    }

    /// Sends one intercepted connection: its header and its descriptor.
    pub fn send_intercepted_stream(
        &mut self,
        header: &InterceptedStreamHeader,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), HandoffError> {
        self.send_frame(&header.encode()?, &[descriptor])
    }
}

impl AsFd for HandoffSender {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

/// The reading end of a hand-off socket. It keeps a partly read frame across
/// calls, so on a non-blocking socket `WouldBlock` mid-frame resumes where it
/// stopped. A framing error (descriptors where none may be, a frame over the
/// limit, end of file inside a frame) poisons it, and every descriptor it was
/// holding is closed.
pub struct HandoffReceiver {
    socket: OwnedFd,
    partial: Partial,
    poisoned: bool,
}

#[derive(Default)]
struct Partial {
    prefix: [u8; 2],
    prefix_read: usize,
    body: Option<Vec<u8>>,
    body_read: usize,
    descriptors: Vec<OwnedFd>,
}

impl HandoffReceiver {
    /// Takes an `AF_UNIX` `SOCK_STREAM` socket. It never asks for the peer
    /// (macOS reports a closed one as not connected): a closed peer shows at
    /// the first send or receive.
    pub fn new(socket: OwnedFd) -> Result<Self, HandoffError> {
        if !is_unix_stream(socket.as_fd()) {
            return Err(HandoffError::Io);
        }
        Ok(Self {
            socket,
            partial: Partial::default(),
            poisoned: false,
        })
    }

    /// Receives one frame: a body of at most `max_len` bytes and at most
    /// `max_descriptors` descriptors. End of file between frames is `Closed`.
    pub fn recv_frame(
        &mut self,
        max_len: usize,
        max_descriptors: usize,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), HandoffError> {
        self.recv_frame_with(max_len, max_descriptors, RECEIVE_FLAGS)
    }

    fn recv_frame_with(
        &mut self,
        max_len: usize,
        max_descriptors: usize,
        flags: RecvFlags,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), HandoffError> {
        if self.poisoned {
            return Err(HandoffError::Poisoned);
        }
        match self.advance(max_len, max_descriptors, flags) {
            Ok(()) => {
                let partial = mem::take(&mut self.partial);
                Ok((partial.body.unwrap_or_default(), partial.descriptors))
            }
            Err(HandoffError::WouldBlock) => Err(HandoffError::WouldBlock),
            Err(HandoffError::Closed) => Err(HandoffError::Closed),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    /// Reads the socket's first frame and requires it to be the role tag,
    /// [`HANDOFF_ROLE_TAG`] with no descriptors, within `timeout`. Anything
    /// else, or nothing in time, poisons the receiver: the peer is not the
    /// broker, or not in step with it. Works on a blocking or non-blocking
    /// socket and leaves its mode alone: each receive is `MSG_DONTWAIT`, and
    /// it waits only in `poll`, never past `timeout`.
    pub fn expect_role_tag(&mut self, timeout: Duration) -> Result<(), HandoffError> {
        let deadline = Instant::now() + timeout;
        let (body, descriptors) = loop {
            match self.recv_frame_with(
                HANDOFF_ROLE_TAG.len(),
                0,
                RECEIVE_FLAGS.union(RecvFlags::DONTWAIT),
            ) {
                Ok(frame) => break frame,
                Err(HandoffError::WouldBlock) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() || !wait_readable(self.socket.as_fd(), left) {
                        self.poison();
                        return Err(HandoffError::RoleTag);
                    }
                }
                Err(HandoffError::Poisoned) => return Err(HandoffError::Poisoned),
                Err(HandoffError::Closed) => {
                    self.poison();
                    return Err(HandoffError::Closed);
                }
                Err(_) => {
                    self.poison();
                    return Err(HandoffError::RoleTag);
                }
            }
        };
        if body != HANDOFF_ROLE_TAG || !descriptors.is_empty() {
            self.poison();
            return Err(HandoffError::RoleTag);
        }
        Ok(())
    }

    /// Unusable for good. Every descriptor held is closed, and the socket is
    /// shut down both ways, instead of the peer queueing work nobody will
    /// read: the peer's next receive reads end of file, and its next send
    /// fails with `Closed`. On macOS only a send carrying descriptors fails;
    /// plain bytes still go through, so there end of file is the signal.
    fn poison(&mut self) {
        self.partial = Partial::default();
        self.poisoned = true;
        // Best effort: a peer already gone has nothing left to tell.
        let _ = rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Both);
    }

    /// Receives one intercepted connection: exactly one descriptor, a
    /// connected Unix stream, and a valid header. A descriptor that is not a
    /// connected Unix stream is refused and closed, and this receiver stays
    /// usable; a caller that trusts its peer, such as the front door, may
    /// still end the whole hand-off over it.
    /// A frame with no descriptor (a repeated role tag, say), more than one
    /// descriptor, or a header that does not decode is a protocol error: the
    /// broker is a trusted peer and every received stream must have a known
    /// id, so every descriptor is closed and the receiver is poisoned.
    pub fn recv_intercepted_stream(
        &mut self,
    ) -> Result<(InterceptedStreamHeader, OwnedFd), HandoffError> {
        let (body, mut descriptors) = self.recv_frame(HANDOFF_MAX_LEN, 1)?;
        if descriptors.is_empty() {
            // The broker sends a frame without a descriptor only as the role
            // tag, once, first: another one here is out of step.
            self.poison();
            return Err(HandoffError::Descriptors);
        }
        if !is_connected_unix_stream(descriptors[0].as_fd()) {
            return Err(HandoffError::Descriptors);
        }
        match InterceptedStreamHeader::decode(&body) {
            Ok(header) => Ok((header, descriptors.remove(0))),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    fn advance(
        &mut self,
        max_len: usize,
        max_descriptors: usize,
        flags: RecvFlags,
    ) -> Result<(), HandoffError> {
        while self.partial.prefix_read < 2 {
            let first = self.partial.prefix_read == 0;
            let at = self.partial.prefix_read;
            let read = read_some(
                self.socket.as_fd(),
                &mut self.partial.prefix[at..],
                first.then_some(&mut self.partial.descriptors),
                flags,
            )?;
            if read == 0 {
                return Err(if first && self.partial.descriptors.is_empty() {
                    HandoffError::Closed
                } else {
                    HandoffError::Io
                });
            }
            self.partial.prefix_read += read;
            if self.partial.descriptors.len() > max_descriptors {
                return Err(HandoffError::Descriptors);
            }
        }
        let length = usize::from(u16::from_le_bytes(self.partial.prefix));
        if length > max_len {
            return Err(HandoffError::Malformed);
        }
        let body = self.partial.body.get_or_insert_with(|| vec![0; length]);
        while self.partial.body_read < body.len() {
            let read = read_some(
                self.socket.as_fd(),
                &mut body[self.partial.body_read..],
                None,
                flags,
            )?;
            if read == 0 {
                return Err(HandoffError::Io);
            }
            self.partial.body_read += read;
        }
        Ok(())
    }
}

impl AsFd for HandoffReceiver {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl AsRawFd for HandoffReceiver {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// A connected, close-on-exec `AF_UNIX` `SOCK_STREAM` pair: a hand-off socket
/// or an intercepted connection. macOS has no `SOCK_CLOEXEC`, so there each
/// end is marked close-on-exec right after it is made.
pub fn stream_pair() -> Result<(OwnedFd, OwnedFd), HandoffError> {
    #[cfg(target_os = "linux")]
    let flags = rustix::net::SocketFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = rustix::net::SocketFlags::empty();
    let (one, two) = rustix::net::socketpair(AddressFamily::UNIX, SocketType::STREAM, flags, None)
        .map_err(|_| HandoffError::Io)?;
    #[cfg(not(target_os = "linux"))]
    for end in [&one, &two] {
        rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC).map_err(|_| HandoffError::Io)?;
    }
    Ok((one, two))
}

fn is_would_block(error: rustix::io::Errno) -> bool {
    error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK
}

/// An `AF_UNIX` `SOCK_STREAM` socket.
fn is_unix_stream(socket: BorrowedFd<'_>) -> bool {
    rustix::net::sockopt::socket_type(socket).is_ok_and(|kind| kind == SocketType::STREAM)
        && rustix::net::getsockname(socket)
            .is_ok_and(|address| address.address_family() == AddressFamily::UNIX)
}

/// A connected `AF_UNIX` `SOCK_STREAM` socket, never a listener.
pub fn is_connected_unix_stream(socket: BorrowedFd<'_>) -> bool {
    is_unix_stream(socket) && rustix::net::getpeername(socket).is_ok()
}

/// One `recvmsg` into `buffer`. Descriptors are taken only into
/// `descriptors`; any other ancillary data, a truncated control message, or
/// descriptors where none are allowed is `Descriptors`, and what arrived is
/// closed.
fn read_some(
    socket: BorrowedFd<'_>,
    buffer: &mut [u8],
    descriptors: Option<&mut Vec<OwnedFd>>,
    flags: RecvFlags,
) -> Result<usize, HandoffError> {
    let mut vectors = [IoSliceMut::new(buffer)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FRAME_MAX_DESCRIPTORS))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = loop {
        match recvmsg(socket, &mut vectors, &mut ancillary, flags) {
            Ok(message) => break message,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) if is_would_block(error) => return Err(HandoffError::WouldBlock),
            Err(_) => return Err(HandoffError::Io),
        }
    };
    let mut received = Vec::new();
    let mut other_ancillary = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(fds) => received.extend(fds),
            _ => other_ancillary = true,
        }
    }
    #[cfg(not(target_os = "linux"))]
    for descriptor in &received {
        rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| HandoffError::Io)?;
    }
    if other_ancillary || message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(HandoffError::Descriptors);
    }
    match descriptors {
        Some(into) => into.extend(received),
        None if !received.is_empty() => return Err(HandoffError::Descriptors),
        None => {}
    }
    Ok(message.bytes)
}

/// Waits until `socket` is readable or has hung up, for at most `timeout`.
fn wait_readable(socket: BorrowedFd<'_>, timeout: Duration) -> bool {
    let mut fds = [rustix::event::PollFd::new(
        &socket,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::event::Timespec::try_from(timeout).ok();
    matches!(rustix::event::poll(&mut fds, timeout.as_ref()), Ok(n) if n > 0)
}
