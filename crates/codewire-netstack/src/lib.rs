//! Transport-neutral userspace TCP/IP netstack.
//!
//! This crate turns bare-IP packet channels into ordinary async TCP
//! listeners and streams using [`smoltcp`]. It also exposes strict DNS-only
//! packet parsing and bounded reply construction, but owns no resolver, TUN,
//! WireGuard, VMM, host socket, policy, or credential behavior. Tailnet and
//! local VM networking supply those transports and policies independently.
//!
//! # Boundary
//!
//! A [`Netstack`] is constructed from a **packet I/O channel pair**:
//! inbound bare IP packets in (`mpsc::Receiver<Vec<u8>>`), and outbound IP
//! packets out (`mpsc::Sender<Vec<u8>>`). The netstack
//! knows nothing about the packet transport, which makes the same engine
//! usable behind an authenticated VM stream or an encrypted peer tunnel.
//!
//! # Public API
//!
//! - [`Netstack::bind`] accepts TCP for a local port.
//! - [`Netstack::bind_endpoint`] accepts TCP for one exact address and port.
//! - [`Netstack::connect`] initiates TCP over the supplied packet transport.
//! - [`TcpStream`] implements `AsyncRead + AsyncWrite`.
//! - [`parse_initial_ipv4_tcp_syn`] surfaces a strict initial flow before bind.
//! - [`parse_ipv4_dns_question`] and [`build_ipv4_dns_response`] admit bounded
//!   DNS without exposing a general UDP socket.
//!
//! All internal queues and live socket counts are bounded by
//! [`NetstackLimits`], and construction rejects packet-channel capacities above
//! that limit. The consumer-owned transport must also cap each packet before
//! enqueueing it; this device rejects packets outside the configured MTU when
//! dequeued. Consumers still own admission, DNS, egress policy,
//! connected-stream injection, and the authenticated packet transport.

mod device;
mod dns;
mod driver;
mod ingress;
mod stream;

pub use dns::{
    build_ipv4_dns_response, parse_ipv4_dns_question, DnsAnswer, DnsBoundaryError, DnsQuestion,
    DnsRecordType,
};
pub use ingress::{
    parse_canonical_ipv4_tcp_packet, parse_initial_ipv4_tcp_syn, CanonicalIpv4TcpPacket,
    InitialTcpSyn, InitialTcpSynError,
};
pub use stream::{TcpListener, TcpStream};

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};
use tokio::sync::{mpsc, oneshot};

use device::ChannelDevice;
use driver::{Command, DriverHandle};

/// A running userspace netstack bound to a single interface IP.
///
/// Cloneable handle semantics are intentionally *not* exposed; a `Netstack`
/// owns the driver task's command channel. Drop it (and the inbound sender) to
/// shut the stack down.
pub struct Netstack {
    handle: DriverHandle,
}

/// Interface settings for a userspace netstack.
///
/// Consumers use this explicit form to configure MTU, checksum verification,
/// routing, and acceptance of exact unconfigured destination addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetstackConfig {
    pub local_ip: IpAddr,
    pub prefix_len: u8,
    pub mtu: usize,
    pub verify_rx_checksums: bool,
    pub accept_any_ip: bool,
    pub default_gateway: Option<IpAddr>,
}

/// Hard resource limits for one userspace netstack.
///
/// The maximum queued application bytes per direction and connection are
/// `stream_*_queue * stream_chunk_bytes`. Each live TCP socket additionally
/// owns one RX and one TX buffer of `socket_buffer_bytes` bytes. Packet-channel
/// capacities are checked against `max_queued_packets` during construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetstackLimits {
    pub max_listeners: usize,
    pub max_connections: usize,
    pub socket_buffer_bytes: usize,
    pub command_queue: usize,
    pub accept_queue: usize,
    pub stream_send_queue: usize,
    pub stream_receive_queue: usize,
    pub stream_chunk_bytes: usize,
    pub max_queued_packets: usize,
    pub max_packets_per_wake: usize,
    pub tcp_idle_timeout: Duration,
}

impl Default for NetstackLimits {
    fn default() -> Self {
        Self {
            max_listeners: 64,
            max_connections: 256,
            socket_buffer_bytes: 64 * 1024,
            command_queue: 64,
            accept_queue: 16,
            stream_send_queue: 8,
            stream_receive_queue: 8,
            stream_chunk_bytes: 8 * 1024,
            max_queued_packets: 256,
            max_packets_per_wake: 64,
            tcp_idle_timeout: Duration::from_secs(120),
        }
    }
}

impl Netstack {
    /// Create a netstack over a raw packet channel pair.
    ///
    /// * `local_ip` / `prefix_len` — the address and connected prefix.
    /// * `inbound` — IP packets arriving from the consumer-owned transport.
    /// * `outbound` — IP packets the stack emits to that transport.
    pub fn new(
        local_ip: IpAddr,
        prefix_len: u8,
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self::with_config(
            NetstackConfig {
                local_ip,
                prefix_len,
                mtu: 1_500,
                verify_rx_checksums: true,
                accept_any_ip: false,
                default_gateway: None,
            },
            inbound,
            outbound,
        )
        .expect("Netstack::new received a valid IP prefix")
    }

    /// Create a netstack with an explicit route and AnyIP policy.
    pub fn with_config(
        config: NetstackConfig,
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<Vec<u8>>,
    ) -> std::io::Result<Self> {
        Self::with_config_and_limits(config, NetstackLimits::default(), inbound, outbound)
    }

    /// Create a netstack with explicit routing and hard resource limits.
    pub fn with_config_and_limits(
        config: NetstackConfig,
        limits: NetstackLimits,
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<Vec<u8>>,
    ) -> std::io::Result<Self> {
        validate_config(config)?;
        validate_limits(limits)?;
        if inbound.max_capacity() > limits.max_queued_packets
            || outbound.max_capacity() > limits.max_queued_packets
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet channel capacity exceeds the configured netstack limit",
            ));
        }
        let device = ChannelDevice::new(outbound, config.mtu, config.verify_rx_checksums);
        let handle = driver::spawn(
            to_smoltcp_addr(config.local_ip),
            config.prefix_len,
            config.accept_any_ip,
            config.default_gateway.map(to_smoltcp_addr),
            inbound,
            device,
            limits,
        )?;
        Ok(Self { handle })
    }

    /// Bind a TCP listener on `port` at any configured local address.
    pub async fn bind(&self, port: u16) -> std::io::Result<TcpListener> {
        self.bind_listen_endpoint(IpListenEndpoint { addr: None, port })
            .await
    }

    /// Bind a listener to one exact IP and port, including an address that is
    /// accepted through [`NetstackConfig::accept_any_ip`].
    pub async fn bind_endpoint(&self, endpoint: SocketAddr) -> std::io::Result<TcpListener> {
        self.bind_listen_endpoint(IpListenEndpoint {
            addr: Some(to_smoltcp_addr(endpoint.ip())),
            port: endpoint.port(),
        })
        .await
    }

    async fn bind_listen_endpoint(
        &self,
        endpoint: IpListenEndpoint,
    ) -> std::io::Result<TcpListener> {
        if endpoint.port == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP listen port must not be zero",
            ));
        }
        let (reply, rx) = oneshot::channel();
        self.handle
            .cmd_tx
            .send(Command::Bind { endpoint, reply })
            .await
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)?
    }

    /// Bind the one catch-all listener. It accepts every TCP connection whose
    /// destination no explicit listener holds, so a consumer that terminates
    /// arbitrary destinations (with [`NetstackConfig::accept_any_ip`]) needs no
    /// listener per destination. Each SYN gets a socket for exactly its
    /// destination, and only [`NetstackLimits::max_connections`] bounds them;
    /// a SYN beyond it is dropped so the client retries. Explicit listeners
    /// keep precedence. Its [`TcpListener::local_port`] is 0.
    pub async fn bind_catch_all(&self) -> std::io::Result<TcpListener> {
        let (reply, rx) = oneshot::channel();
        self.handle
            .cmd_tx
            .send(Command::BindCatchAll { reply })
            .await
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)?
    }

    /// Dial a TCP connection to `addr` over the packet transport.
    /// Resolves to a [`TcpStream`] once the connect is initiated; reads/writes
    /// drive the handshake to completion (like tokio's `TcpStream::connect`).
    pub async fn connect(&self, addr: std::net::SocketAddr) -> std::io::Result<TcpStream> {
        let remote = IpEndpoint::new(to_smoltcp_addr(addr.ip()), addr.port());
        let (reply, rx) = oneshot::channel();
        self.handle
            .cmd_tx
            .send(Command::Connect { remote, reply })
            .await
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)?
    }
}

fn validate_config(config: NetstackConfig) -> std::io::Result<()> {
    if !(576..=u16::MAX as usize).contains(&config.mtu) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack MTU must be between 576 and 65535 bytes",
        ));
    }
    let max_prefix = if config.local_ip.is_ipv4() { 32 } else { 128 };
    if config.prefix_len > max_prefix {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack prefix does not match its address family",
        ));
    }
    if config
        .default_gateway
        .is_some_and(|gateway| gateway.is_ipv4() != config.local_ip.is_ipv4())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack gateway and interface must use the same address family",
        ));
    }
    Ok(())
}

fn validate_limits(limits: NetstackLimits) -> std::io::Result<()> {
    let nonzero = [
        limits.max_listeners,
        limits.max_connections,
        limits.socket_buffer_bytes,
        limits.command_queue,
        limits.accept_queue,
        limits.stream_send_queue,
        limits.stream_receive_queue,
        limits.stream_chunk_bytes,
        limits.max_queued_packets,
        limits.max_packets_per_wake,
    ];
    if nonzero.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack resource limits must be nonzero",
        ));
    }
    if limits.max_listeners > u16::MAX as usize
        || limits.max_connections > u16::MAX as usize
        || limits.command_queue > u16::MAX as usize
        || limits.accept_queue > u16::MAX as usize
        || limits.stream_send_queue > u16::MAX as usize
        || limits.stream_receive_queue > u16::MAX as usize
        || limits.max_queued_packets > u16::MAX as usize
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack queue or object limit is too large",
        ));
    }
    if !(1024..=16 * 1024 * 1024).contains(&limits.socket_buffer_bytes)
        || limits.stream_chunk_bytes > limits.socket_buffer_bytes
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack socket and stream byte limits are inconsistent",
        ));
    }
    if limits.max_packets_per_wake > limits.max_queued_packets {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack packet batch exceeds its queue limit",
        ));
    }
    if limits.tcp_idle_timeout < Duration::from_secs(1)
        || limits.tcp_idle_timeout > Duration::from_secs(24 * 60 * 60)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "netstack TCP idle timeout must be between one second and one day",
        ));
    }
    Ok(())
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
