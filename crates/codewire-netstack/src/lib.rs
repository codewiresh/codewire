//! Transport-neutral userspace TCP/IP netstack.
//!
//! This crate turns bare-IP packet channels into ordinary async TCP
//! listeners and streams using [`smoltcp`]. It owns no TUN, WireGuard, VMM,
//! host socket, DNS, policy, or credential behavior. Tailnet and local VM
//! networking supply those transports and policies independently.
//!
//! # Boundary
//!
//! A [`Netstack`] is constructed from a **packet I/O channel pair**:
//! inbound bare IP packets in (`mpsc::UnboundedReceiver<Vec<u8>>`), and
//! outbound IP packets out (`mpsc::UnboundedSender<Vec<u8>>`). The netstack
//! knows nothing about the packet transport, which makes the same engine
//! usable behind an authenticated VM stream or an encrypted peer tunnel.
//!
//! # Public API
//!
//! - [`Netstack::bind`] accepts TCP for a local port.
//! - [`Netstack::bind_endpoint`] accepts TCP for one exact address and port.
//! - [`Netstack::connect`] initiates TCP over the supplied packet transport.
//! - [`TcpStream`] implements `AsyncRead + AsyncWrite`.
//!
//! The stream queues are intentionally unchanged during the extraction. The
//! local VM consumer must not ship until its separate feasibility gate adds
//! and proves hard packet, connection, and byte bounds.

mod device;
mod driver;
mod stream;

pub use stream::{TcpListener, TcpStream};

use std::net::{IpAddr, SocketAddr};

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

impl Netstack {
    /// Create a netstack over a raw packet channel pair.
    ///
    /// * `local_ip` / `prefix_len` — the address and connected prefix.
    /// * `inbound` — IP packets arriving from the consumer-owned transport.
    /// * `outbound` — IP packets the stack emits to that transport.
    pub fn new(
        local_ip: IpAddr,
        prefix_len: u8,
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
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
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    ) -> std::io::Result<Self> {
        validate_config(config)?;
        let device = ChannelDevice::new(outbound, config.mtu, config.verify_rx_checksums);
        let handle = driver::spawn(
            to_smoltcp_addr(config.local_ip),
            config.prefix_len,
            config.accept_any_ip,
            config.default_gateway.map(to_smoltcp_addr),
            inbound,
            device,
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
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)
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
            .map_err(driver_gone)?;
        rx.await.map_err(driver_gone)
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
