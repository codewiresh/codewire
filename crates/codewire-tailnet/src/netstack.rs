//! Tailnet configuration for the shared transport-neutral userspace netstack.

use std::net::{IpAddr, SocketAddr};

use tokio::sync::mpsc;

pub use codewire_netstack::{TcpListener, TcpStream};

pub const POD_NETWORK_MTU: usize = 1230;
pub const WIREGUARD_DATA_PACKET_OVERHEAD: usize = 32;
pub const PEER_RELAY_GENEVE_OVERHEAD: usize = 8;
pub const OUTER_IPV6_UDP_OVERHEAD: usize = 48;
pub const PEER_RELAY_UDP_PAYLOAD_BUDGET: usize = POD_NETWORK_MTU - OUTER_IPV6_UDP_OVERHEAD;
pub const PEER_RELAY_INNER_PACKET_BUDGET: usize =
    PEER_RELAY_UDP_PAYLOAD_BUDGET - WIREGUARD_DATA_PACKET_OVERHEAD - PEER_RELAY_GENEVE_OVERHEAD;

/// MTU advertised to tailnet peers after accounting for the most constrained
/// cross-node peer-relay path.
pub const TUNNEL_MTU: usize = 1130;

const _: () = assert!(TUNNEL_MTU <= PEER_RELAY_INNER_PACKET_BUDGET);

/// Tailnet-compatible wrapper that preserves the existing public constructor
/// while delegating all TCP/IP behavior to `codewire-netstack`.
pub struct Netstack {
    inner: codewire_netstack::Netstack,
}

impl Netstack {
    pub fn new(
        local_ip: IpAddr,
        prefix_len: u8,
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        let inner = codewire_netstack::Netstack::with_config(
            codewire_netstack::NetstackConfig {
                local_ip,
                prefix_len,
                mtu: TUNNEL_MTU,
                // Tailnet packets arrive over authenticated WireGuard and may
                // carry receive-offload-style partial checksums.
                verify_rx_checksums: false,
                accept_any_ip: false,
                default_gateway: None,
            },
            inbound,
            outbound,
        )
        .expect("tailnet address and prefix are valid");
        Self { inner }
    }

    pub async fn bind(&self, port: u16) -> std::io::Result<TcpListener> {
        self.inner.bind(port).await
    }

    pub async fn connect(&self, address: SocketAddr) -> std::io::Result<TcpStream> {
        self.inner.connect(address).await
    }
}
