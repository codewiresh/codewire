//! A supervisor's control channel with a front-door process: one connected
//! Unix stream, framed by `codewire_egress_policy::handoff`, as the hand-off
//! itself is, so there is one transport on Linux and macOS. The local
//! runner's (#3999) and cw-egress's (#4001) front doors both use it.

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};

use codewire_egress_policy::handoff::{HandoffError, HandoffReceiver, HandoffSender};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// Both directions of one control socket. The sender and the receiver hold
/// duplicates of the same socket, which is non-blocking.
pub struct ControlChannel {
    receiver: AsyncFd<HandoffReceiver>,
    sender: HandoffSender,
}

impl ControlChannel {
    /// Take a connected Unix stream socket; it is made non-blocking.
    pub fn new(socket: OwnedFd) -> io::Result<Self> {
        rustix::io::ioctl_fionbio(&socket, true)?;
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&socket, 0)?;
        let sender = HandoffSender::new(duplicate).map_err(not_a_stream)?;
        let receiver = HandoffReceiver::new(socket).map_err(not_a_stream)?;
        // RUSTSEC-2026-0386: an owned socket is outside `AsyncFd::new`'s unsound case; `register` migration is #3249.
        #[allow(deprecated)]
        let receiver = AsyncFd::with_interest(receiver, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self { receiver, sender })
    }

    /// One frame of at most `max_len` bytes and `max_descriptors`
    /// descriptors. Any framing error leaves the channel unusable.
    pub async fn receive(
        &mut self,
        max_len: usize,
        max_descriptors: usize,
    ) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
        loop {
            let mut ready = self.receiver.readable_mut().await?;
            let received = ready.try_io(|receiver| {
                match receiver.get_mut().recv_frame(max_len, max_descriptors) {
                    Err(HandoffError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
                    result => Ok(result),
                }
            });
            // Only a would-block is an error here, and `try_io` turns it into
            // cleared readiness.
            let Ok(Ok(result)) = received else {
                continue;
            };
            return result.map_err(|error| match error {
                HandoffError::Closed => io::ErrorKind::UnexpectedEof.into(),
                _ => io::Error::other("front door control frame refused"),
            });
        }
    }

    /// Send one frame, waiting while the socket is full.
    pub async fn send(&mut self, body: &[u8], descriptors: &[BorrowedFd<'_>]) -> io::Result<()> {
        loop {
            match self.sender.send_frame(body, descriptors) {
                Ok(()) => return Ok(()),
                Err(HandoffError::WouldBlock) => {
                    self.receiver.writable().await?.clear_ready();
                }
                Err(_) => return Err(io::Error::other("front door control frame not sent")),
            }
        }
    }
}

fn not_a_stream(_: HandoffError) -> io::Error {
    io::Error::other("front door control socket is not a connected Unix stream")
}
