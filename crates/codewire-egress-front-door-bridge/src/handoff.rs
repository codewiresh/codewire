//! Streams the egress broker hands to the front door (#3999), received on
//! the async runtime. The framing and the receive itself are
//! `codewire_egress_policy::handoff`'s [`HandoffReceiver`]; this waits for
//! readability and resumes a partly read frame.
//!
//! Each received stream is acknowledged with one frame back, its stream id
//! as eight little-endian bytes and no descriptors: the broker holds its
//! copy of the descriptor until then, because on Darwin a descriptor whose
//! sender closes it while it is in flight can arrive disconnected. It is the
//! only traffic in that direction.

use std::io;
use std::os::fd::OwnedFd;

use codewire_egress_policy::handoff::{
    HandoffError, HandoffReceiver, HandoffSender, InterceptedStreamHeader,
};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// The front door's end of the supervisor's hand-off socket: the receiver,
/// and a sender on a duplicate of the same end for acknowledgements.
pub struct HandoffSocket {
    receiver: AsyncFd<HandoffReceiver>,
    acknowledgements: HandoffSender,
}

/// One received message: a stream with its header, or the broker's end
/// closing.
#[derive(Debug)]
pub enum Received {
    Stream(InterceptedStreamHeader, OwnedFd),
    Closed,
}

/// A frame the broker should never send. The broker is a trusted peer, so
/// any of these is a protocol error that ends the hand-off socket: the
/// broker then sees it close and drops every copy it holds. Carries no peer
/// input, so it may be logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    #[error("hand-off header is malformed")]
    Header,
    #[error("hand-off header version is not 1")]
    Version,
    #[error("hand-off frame does not carry one connected Unix stream")]
    Descriptor,
}

impl HandoffSocket {
    /// Take the front door's end: a connected Unix stream socket, made
    /// non-blocking here.
    pub fn new(socket: OwnedFd) -> io::Result<Self> {
        if !connected_unix_stream(&socket) {
            return Err(io::Error::other(
                "hand-off socket is not a connected Unix stream",
            ));
        }
        rustix::io::ioctl_fionbio(&socket, true)?;
        let not_a_stream = |_| io::Error::other("hand-off socket is not a connected Unix stream");
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&socket, 0)?;
        let acknowledgements = HandoffSender::new(duplicate).map_err(not_a_stream)?;
        let receiver = HandoffReceiver::new(socket).map_err(not_a_stream)?;
        // RUSTSEC-2026-0386: an owned socket is outside `AsyncFd::new`'s unsound case; `register` migration is #3249.
        #[allow(deprecated)]
        let receiver = AsyncFd::with_interest(receiver, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self {
            receiver,
            acknowledgements,
        })
    }

    /// Tell the broker the stream `stream_id` arrived, so it drops its copy.
    /// Waits while the socket is full; any other failure is the socket's.
    pub async fn acknowledge(&mut self, stream_id: u64) -> io::Result<()> {
        loop {
            match self
                .acknowledgements
                .send_frame(&stream_id.to_le_bytes(), &[])
            {
                Ok(()) => return Ok(()),
                Err(HandoffError::WouldBlock) => {
                    self.receiver.writable().await?.clear_ready();
                }
                Err(_) => return Err(io::Error::other("hand-off acknowledgement failed")),
            }
        }
    }

    /// The next message. An error is the socket failing or a
    /// [`ProtocolError`] (`io::ErrorKind::InvalidData`); either way the
    /// socket is done.
    pub async fn receive(&mut self) -> io::Result<Received> {
        loop {
            let mut ready = self.receiver.readable_mut().await?;
            let received =
                ready.try_io(
                    |receiver| match receiver.get_mut().recv_intercepted_stream() {
                        Err(HandoffError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
                        result => Ok(result),
                    },
                );
            // Only a would-block is an error here, and `try_io` turns it into
            // cleared readiness.
            let Ok(Ok(result)) = received else {
                continue;
            };
            return match result {
                Ok((header, stream)) => Ok(Received::Stream(header, stream)),
                Err(HandoffError::Closed) => Ok(Received::Closed),
                Err(HandoffError::Malformed) => Err(protocol(ProtocolError::Header)),
                Err(HandoffError::Version) => Err(protocol(ProtocolError::Version)),
                Err(HandoffError::Descriptors) => Err(protocol(ProtocolError::Descriptor)),
                Err(HandoffError::Io | HandoffError::Poisoned | HandoffError::WouldBlock) => {
                    Err(io::Error::other("hand-off socket failed"))
                }
            };
        }
    }
}

fn protocol(error: ProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// A connected `AF_UNIX` `SOCK_STREAM` socket that closes on exec. The
/// receiver no longer checks its end, so the front door does, whoever
/// passed it.
fn connected_unix_stream(socket: &OwnedFd) -> bool {
    let unix = rustix::net::getsockname(socket)
        .is_ok_and(|address| address.address_family() == rustix::net::AddressFamily::UNIX);
    unix && rustix::net::sockopt::socket_type(socket) == Ok(rustix::net::SocketType::STREAM)
        && rustix::io::fcntl_getfd(socket)
            .is_ok_and(|flags| flags.contains(rustix::io::FdFlags::CLOEXEC))
        && rustix::net::getpeername(socket).is_ok()
}

#[cfg(test)]
mod tests;
