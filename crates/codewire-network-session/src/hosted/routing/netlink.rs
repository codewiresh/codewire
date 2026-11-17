//! A blocking route netlink socket: one request at a time, acknowledged or
//! dumped, with no async runtime. Every receive waits at most until the
//! socket's deadline, so neither the init container nor the self-check can
//! hang on a kernel that does not answer.

use std::io;
use std::time::Instant;

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use rustix::net::sockopt::{Timeout, set_socket_timeout};

use super::RoutingError;

const RECEIVE_BYTES: usize = 64 * 1024;

pub(super) struct RouteSocket {
    socket: Socket,
    sequence: u32,
    deadline: Instant,
}

impl RouteSocket {
    /// A socket whose every exchange must finish by `deadline`.
    pub(super) fn open(deadline: Instant) -> Result<Self, RoutingError> {
        let mut socket = Socket::new(NETLINK_ROUTE).map_err(RoutingError::Netlink)?;
        socket.bind_auto().map_err(RoutingError::Netlink)?;
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(RoutingError::Netlink)?;
        Ok(Self {
            socket,
            sequence: 0,
            deadline,
        })
    }

    /// Send `message` with `flags` and wait for the kernel's acknowledgement.
    pub(super) fn request(
        &mut self,
        step: &'static str,
        message: RouteNetlinkMessage,
        flags: u16,
    ) -> Result<(), RoutingError> {
        let sequence = self.send(message, flags | NLM_F_REQUEST | NLM_F_ACK)?;
        let mut buffer = vec![0_u8; RECEIVE_BYTES];
        loop {
            for reply in self.receive(&mut buffer)? {
                if reply.header.sequence_number != sequence {
                    continue;
                }
                match reply.payload {
                    NetlinkPayload::Error(error) => {
                        return match error.code {
                            None => Ok(()),
                            Some(_) => Err(RoutingError::Kernel {
                                step,
                                source: error.to_io(),
                            }),
                        };
                    }
                    _ => continue,
                }
            }
        }
    }

    /// Every message the kernel answers `message` with as a dump.
    pub(super) fn dump(
        &mut self,
        message: RouteNetlinkMessage,
    ) -> Result<Vec<RouteNetlinkMessage>, RoutingError> {
        let sequence = self.send(message, NLM_F_REQUEST | NLM_F_DUMP)?;
        let mut buffer = vec![0_u8; RECEIVE_BYTES];
        let mut found = Vec::new();
        loop {
            for reply in self.receive(&mut buffer)? {
                if reply.header.sequence_number != sequence {
                    continue;
                }
                match reply.payload {
                    NetlinkPayload::Done(_) => return Ok(found),
                    NetlinkPayload::Error(error) => {
                        return Err(RoutingError::Kernel {
                            step: "read back the routing",
                            source: error.to_io(),
                        });
                    }
                    NetlinkPayload::InnerMessage(inner) => found.push(inner),
                    _ => {}
                }
            }
        }
    }

    fn send(&mut self, message: RouteNetlinkMessage, flags: u16) -> Result<u32, RoutingError> {
        self.sequence = self.sequence.wrapping_add(1);
        let mut header = NetlinkHeader::default();
        header.flags = flags;
        header.sequence_number = self.sequence;
        let mut packet = NetlinkMessage::new(header, NetlinkPayload::from(message));
        packet.finalize();
        let mut bytes = vec![0_u8; packet.buffer_len()];
        packet.serialize(&mut bytes);
        self.socket.send(&bytes, 0).map_err(RoutingError::Netlink)?;
        Ok(self.sequence)
    }

    /// The messages in one datagram from the kernel, by the deadline.
    fn receive(
        &self,
        buffer: &mut [u8],
    ) -> Result<Vec<NetlinkMessage<RouteNetlinkMessage>>, RoutingError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(RoutingError::TimedOut);
        }
        set_socket_timeout(&self.socket, Timeout::Recv, Some(remaining))
            .map_err(|error| RoutingError::Netlink(error.into()))?;
        let size = match self.socket.recv(&mut &mut buffer[..], 0) {
            Ok(size) => size,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(RoutingError::TimedOut);
            }
            Err(error) => return Err(RoutingError::Netlink(error)),
        };
        let mut messages = Vec::new();
        let mut offset = 0;
        while offset < size {
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buffer[offset..size])
                .map_err(|_| RoutingError::Malformed)?;
            let length = usize::try_from(message.header.length).unwrap_or(0);
            if length == 0 {
                break;
            }
            offset += length;
            messages.push(message);
        }
        Ok(messages)
    }
}
