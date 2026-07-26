//! A [`smoltcp::phy::Device`] backed by a packet I/O channel.
//!
//! This is the seam the WireGuard layer will eventually drive. smoltcp speaks
//! only to a `Device`; we make that `Device` read inbound IP packets from a
//! queue (filled from the inbound channel before each poll) and write outbound
//! IP packets to an unbounded sender (drained by whoever owns the other side —
//! in the loopback proof, the peer netstack's inbound channel; in production,
//! the WireGuard encrypt-and-send path).
//!
//! Medium is [`Medium::Ip`]: the tunnel carries bare IP packets with no
//! Ethernet/L2 framing, exactly like gvisor's `channel.Endpoint` on the Go side.

use std::collections::VecDeque;

use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};
use tokio::sync::mpsc::UnboundedSender;

/// Cross-node pod-network MTU budget in the current dev/prod topology.
///
/// The tailnet's UDP paths (direct and shared peer relay) must survive the
/// most constrained underlay hop. In the current clusters that hop is pod
/// networking at MTU 1230 (Cilium VXLAN over the nodes' tailscale mesh:
/// 1280 - 50). A tunnel IP packet gains WireGuard (16 header + 16 tag),
/// Geneve (8) on the peer-relay path, outer UDP (8), and an outer IP header
/// (40 for IPv6), so the inner packet must stay at or below
/// 1230 - 32 - 8 - 8 - 40 = 1142. We advertise 1130 for margin.
pub const POD_NETWORK_MTU: usize = 1230;
pub const WIREGUARD_DATA_PACKET_OVERHEAD: usize = 32;
pub const PEER_RELAY_GENEVE_OVERHEAD: usize = 8;
pub const OUTER_IPV6_UDP_OVERHEAD: usize = 48;
pub const PEER_RELAY_UDP_PAYLOAD_BUDGET: usize = POD_NETWORK_MTU - OUTER_IPV6_UDP_OVERHEAD;
pub const PEER_RELAY_INNER_PACKET_BUDGET: usize =
    PEER_RELAY_UDP_PAYLOAD_BUDGET - WIREGUARD_DATA_PACKET_OVERHEAD - PEER_RELAY_GENEVE_OVERHEAD;

/// MTU advertised to smoltcp, which also sets the TCP MSS we advertise to
/// peers — the lever that keeps Go tailnet clients' segments deliverable.
///
/// The conventional tailnet MTU is 1280, but a larger value here only helps
/// same-node pod placements where eBPF redirects skip the MTU check — which
/// made oversized segments work or vanish depending on where the relay pod
/// landed. A single conservative value keeps the data plane placement-proof;
/// DERP (stream transport) is unaffected either way.
pub const TUNNEL_MTU: usize = 1130;

const _: () = assert!(TUNNEL_MTU <= PEER_RELAY_INNER_PACKET_BUDGET);

/// A channel-backed smoltcp device.
///
/// `inbound` is the staging queue the [`super::driver`] fills from the inbound
/// packet channel immediately before each `poll`; smoltcp drains it via
/// `receive`. `outbound` is where smoltcp hands us packets to emit.
pub struct ChannelDevice {
    pub(crate) inbound: VecDeque<Vec<u8>>,
    pub(crate) outbound: UnboundedSender<Vec<u8>>,
}

impl ChannelDevice {
    pub fn new(outbound: UnboundedSender<Vec<u8>>) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound,
        }
    }

    /// Stage an inbound IP packet for the next `poll`.
    pub fn push_inbound(&mut self, pkt: Vec<u8>) {
        log_tcp_packet("inbound", &pkt);
        self.inbound.push_back(pkt);
    }

    /// Whether there is staged inbound work (used to decide whether another
    /// immediate poll is warranted).
    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        // Tunnel peers validate checksums off the wire (tailscale's netstack
        // drops any packet whose IPv4/TCP/UDP checksum does not verify), so
        // every emitted packet must carry a computed checksum. Inbound packets
        // already arrive over authenticated WireGuard, so skipping RX
        // verification is safe and tolerates offload-style partial checksums.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.inbound.pop_front()?;
        let rx = RxToken { buffer };
        let tx = TxToken {
            outbound: &self.outbound,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            outbound: &self.outbound,
        })
    }
}

/// One inbound packet handed to smoltcp for parsing.
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// One outbound packet slot. smoltcp serializes a packet into the buffer; on
/// consume we ship it down the outbound channel. A closed receiver just means
/// the far side is gone — drop the packet (the TCP retransmit/teardown logic
/// will notice via timeouts), which keeps `transmit` infallible as the trait
/// requires.
pub struct TxToken<'a> {
    outbound: &'a UnboundedSender<Vec<u8>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        log_tcp_packet("outbound", &buffer);
        let _ = self.outbound.send(buffer);
        result
    }
}

fn log_tcp_packet(direction: &'static str, pkt: &[u8]) {
    let parsed = if let Ok(ip) = Ipv6Packet::new_checked(pkt) {
        if ip.next_header() != IpProtocol::Tcp {
            return;
        }
        Some((
            IpAddress::Ipv6(ip.src_addr()),
            IpAddress::Ipv6(ip.dst_addr()),
            ip.payload(),
        ))
    } else if let Ok(ip) = Ipv4Packet::new_checked(pkt) {
        if ip.next_header() != IpProtocol::Tcp {
            return;
        }
        Some((
            IpAddress::Ipv4(ip.src_addr()),
            IpAddress::Ipv4(ip.dst_addr()),
            ip.payload(),
        ))
    } else {
        None
    };

    let Some((src_ip, dst_ip, payload)) = parsed else {
        tracing::debug!(
            direction,
            packet_len = pkt.len(),
            "rust tailnet netstack TCP packet parse skipped"
        );
        return;
    };

    let Ok(tcp) = TcpPacket::new_checked(payload) else {
        tracing::debug!(
            direction,
            packet_len = pkt.len(),
            src_ip = %src_ip,
            dst_ip = %dst_ip,
            "rust tailnet netstack TCP packet parse failed"
        );
        return;
    };

    tracing::debug!(
        direction,
        packet_len = pkt.len(),
        src_ip = %src_ip,
        dst_ip = %dst_ip,
        src_port = tcp.src_port(),
        dst_port = tcp.dst_port(),
        seq = %tcp.seq_number(),
        ack = %tcp.ack_number(),
        ack_flag = tcp.ack(),
        syn = tcp.syn(),
        fin = tcp.fin(),
        rst = tcp.rst(),
        psh = tcp.psh(),
        window_len = tcp.window_len(),
        payload_len = tcp.payload().len(),
        "rust tailnet netstack TCP packet"
    );
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::Device;

    use super::*;

    #[test]
    fn channel_device_uses_virtual_tunnel_checksum_capabilities() {
        let (outbound, _rx) = tokio::sync::mpsc::unbounded_channel();
        let device = ChannelDevice::new(outbound);
        let caps = device.capabilities();

        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, TUNNEL_MTU);
        assert!(!caps.checksum.ipv4.rx());
        assert!(caps.checksum.ipv4.tx());
        assert!(!caps.checksum.tcp.rx());
        assert!(caps.checksum.tcp.tx());
        assert!(!caps.checksum.udp.rx());
        assert!(caps.checksum.udp.tx());
    }
}
