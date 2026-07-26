//! Userspace TCP/IP netstack (#59) — the gvisor-`netstack` equivalent that
//! turns the WireGuard tunnel into ordinary `Listen`/`Dial`.
//!
//! The workspace/gateway run **unprivileged** (no kernel TUN), so the TCP/IP
//! stack must live in userspace. The Go side ([`libs/tailnet/conn.go`]) wraps
//! gvisor's `netstack` to expose `Listen("tcp", ":22")` and `DialContextTCP`
//! over the WireGuard device. This module is the Rust equivalent, built on
//! [`smoltcp`].
//!
//! # Boundary
//!
//! A [`Netstack`] is constructed from a **packet I/O channel pair**:
//! inbound decrypted IP packets in (`mpsc::UnboundedReceiver<Vec<u8>>`), and
//! outbound IP packets out (`mpsc::UnboundedSender<Vec<u8>>`). That is exactly
//! the seam the WireGuard layer (#45) will drive: inbound = packets that came
//! off the tunnel after `Tunn::decapsulate`; outbound = packets to hand to
//! `Tunn::encapsulate`. The netstack itself knows nothing about WireGuard —
//! it only sees bare IP packets — which is what makes the in-process loopback
//! proof possible (wire two netstacks' channels directly to each other).
//!
//! # Public API (maps to the Go `Conn`)
//!
//! | Go (`conn.go`)               | Rust (`Netstack`)         |
//! |------------------------------|---------------------------|
//! | `Conn.Listen("tcp", addr)`   | [`Netstack::bind`]        |
//! | `listener.Accept()`          | [`TcpListener::accept`]   |
//! | `Conn.DialContextTCP(dst)`   | [`Netstack::connect`]     |
//! | returned `net.Conn`          | [`TcpStream`] (`AsyncRead + AsyncWrite`) |
//!
//! The future `Conn` (#59) can adopt this shape directly: it will own the
//! WireGuard `Tunn`, pump decapsulated packets into `inbound`, and forward
//! `outbound` packets through `encapsulate` — without changing this API.
//!
//! # Deferred to the `Conn` wiring (#59)
//!
//! - WireGuard glue (this spike uses raw packet channels).
//! - Multiple local addresses / routing table beyond the single self-IP.
//! - Write backpressure / bounded buffers (spike uses unbounded tx queues).
//! - Address-family/host parsing in `bind`/`connect` arguments to match the
//!   Go `net.SplitHostPort` string API exactly (spike takes typed addrs).

mod device;
mod driver;
mod stream;

pub use device::{PEER_RELAY_UDP_PAYLOAD_BUDGET, TUNNEL_MTU, WIREGUARD_DATA_PACKET_OVERHEAD};
pub use stream::{TcpListener, TcpStream};

use std::net::IpAddr;

use smoltcp::wire::{IpAddress, IpEndpoint};
use tokio::sync::{mpsc, oneshot};

use device::ChannelDevice;
use driver::{Command, DriverHandle};

/// A running userspace netstack bound to a single tailnet IP.
///
/// Cloneable handle semantics are intentionally *not* exposed; a `Netstack`
/// owns the driver task's command channel. Drop it (and the inbound sender) to
/// shut the stack down.
pub struct Netstack {
    handle: DriverHandle,
}

impl Netstack {
    /// Create a netstack over a raw packet channel pair.
    ///
    /// * `local_ip` / `prefix_len` — the tailnet address smoltcp answers for
    ///   (for Codewire, a `fd7a:115c:a1e0::/48` ULA IPv6 address).
    /// * `inbound` — decrypted IP packets arriving from the tunnel.
    /// * `outbound` — IP packets the stack wants to send (caller encrypts +
    ///   ships them; in the loopback proof, feeds the peer's `inbound`).
    pub fn new(
        local_ip: IpAddr,
        prefix_len: u8,
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        let device = ChannelDevice::new(outbound);
        let handle = driver::spawn(to_smoltcp_addr(local_ip), prefix_len, inbound, device);
        Self { handle }
    }

    /// Bind a TCP listener on `port` (any local address), mirroring
    /// `Conn.Listen("tcp", ":port")`. The returned [`TcpListener::accept`]
    /// yields inbound [`TcpStream`]s.
    pub async fn bind(&self, port: u16) -> std::io::Result<TcpListener> {
        let (reply, rx) = oneshot::channel();
        self.handle
            .cmd_tx
            .send(Command::Bind { port, reply })
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)
    }

    /// Dial a TCP connection to `addr`, mirroring `Conn.DialContextTCP(dst)`.
    /// Resolves to a [`TcpStream`] once the connect is initiated; reads/writes
    /// drive the handshake to completion (like tokio's `TcpStream::connect`).
    pub async fn connect(&self, addr: std::net::SocketAddr) -> std::io::Result<TcpStream> {
        let remote = IpEndpoint::new(to_smoltcp_addr(addr.ip()), addr.port());
        let (reply, rx) = oneshot::channel();
        self.handle
            .cmd_tx
            .send(Command::Connect { remote, reply })
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)
    }
}

fn to_smoltcp_addr(ip: IpAddr) -> IpAddress {
    // smoltcp 0.13's wire address types are newtypes over `core::net`, so we
    // can construct them directly from the std octets.
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(v4.octets())),
        IpAddr::V6(v6) => IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(v6.octets())),
    }
}

fn driver_gone<E>(_: E) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "netstack driver task is gone",
    )
}

#[cfg(test)]
mod tests;
