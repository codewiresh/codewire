//! A [`smoltcp::phy::Device`] backed by a packet I/O channel.
//!
//! smoltcp speaks only to a `Device`; this adapter reads inbound IP packets from a
//! queue (filled from the inbound channel before each poll) and writes outbound
//! IP packets to a bounded sender (drained by whoever owns the other side —
//! in the loopback proof, the peer netstack's inbound channel).
//!
//! Medium is [`Medium::Ip`]: the transport carries bare IP packets with no
//! Ethernet/L2 framing.

use std::collections::VecDeque;

use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};
use tokio::sync::mpsc::Sender;

/// A channel-backed smoltcp device.
///
/// `inbound` is the staging queue the [`super::driver`] fills from the inbound
/// packet channel immediately before each `poll`; smoltcp drains it via
/// `receive`. `outbound` is where smoltcp hands us packets to emit.
pub struct ChannelDevice {
    pub(crate) inbound: VecDeque<Vec<u8>>,
    pub(crate) outbound: Sender<Vec<u8>>,
    mtu: usize,
    verify_rx_checksums: bool,
}

impl ChannelDevice {
    pub fn new(outbound: Sender<Vec<u8>>, mtu: usize, verify_rx_checksums: bool) -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound,
            mtu,
            verify_rx_checksums,
        }
    }

    /// Stage an inbound IP packet for the next `poll`.
    pub fn push_inbound(&mut self, pkt: Vec<u8>) -> bool {
        if !(20..=self.mtu).contains(&pkt.len()) {
            tracing::debug!(
                packet_len = pkt.len(),
                mtu = self.mtu,
                "rust userspace netstack dropped invalid-size inbound packet"
            );
            return false;
        }
        log_tcp_packet("inbound", &pkt);
        self.inbound.push_back(pkt);
        true
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
        caps.max_transmission_unit = self.mtu;
        // Every emitted packet carries a computed checksum. Consumers choose
        // whether inbound checksums must be verified: hostile VM input enables
        // it, while an authenticated transport with receive-offload-style
        // partial checksums may disable only the RX side.
        let checksum = if self.verify_rx_checksums {
            Checksum::Both
        } else {
            Checksum::Tx
        };
        caps.checksum.ipv4 = checksum;
        caps.checksum.tcp = checksum;
        caps.checksum.udp = checksum;
        caps.checksum.icmpv4 = checksum;
        caps.checksum.icmpv6 = checksum;
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
    outbound: &'a Sender<Vec<u8>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        log_tcp_packet("outbound", &buffer);
        if let Err(error) = self.outbound.try_send(buffer) {
            let queue_closed = matches!(error, tokio::sync::mpsc::error::TrySendError::Closed(_));
            tracing::debug!(
                queue_closed,
                "rust userspace netstack dropped outbound packet at bounded queue"
            );
        }
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
            "rust userspace netstack TCP packet parse skipped"
        );
        return;
    };

    let Ok(tcp) = TcpPacket::new_checked(payload) else {
        tracing::debug!(
            direction,
            packet_len = pkt.len(),
            src_ip = %src_ip,
            dst_ip = %dst_ip,
            "rust userspace netstack TCP packet parse failed"
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
        "rust userspace netstack TCP packet"
    );
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::Device;

    use super::*;

    #[test]
    fn channel_device_uses_configured_mtu_and_checksum_capabilities() {
        let (outbound, _rx) = tokio::sync::mpsc::channel(8);
        let mut device = ChannelDevice::new(outbound, 1500, true);
        let caps = device.capabilities();

        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1500);
        assert!(caps.checksum.ipv4.rx());
        assert!(caps.checksum.ipv4.tx());
        assert!(caps.checksum.tcp.rx());
        assert!(caps.checksum.tcp.tx());
        assert!(caps.checksum.udp.rx());
        assert!(caps.checksum.udp.tx());
        assert!(!device.push_inbound(vec![0; 19]));
        assert!(!device.push_inbound(vec![0; 1501]));
        assert!(!device.has_inbound());
    }
}
