//! A [`smoltcp::phy::Device`] backed by a packet I/O channel.
//!
//! smoltcp speaks only to a `Device`; this adapter reads inbound IP packets from a
//! queue (filled from the inbound channel before each poll) and writes outbound
//! IP packets to a bounded sender (drained by whoever owns the other side —
//! in the loopback proof, the peer netstack's inbound channel).
//!
//! The outbound queue applies backpressure (#4046). A send token is offered
//! only with a slot already reserved in the queue, so a full queue makes
//! smoltcp keep the data in its socket buffers and retry on a later poll,
//! instead of building a packet that would then be dropped.
//!
//! Medium is [`Medium::Ip`]: the transport carries bare IP packets with no
//! Ethernet/L2 framing.

use std::collections::VecDeque;

use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Permit, Sender};

/// A channel-backed smoltcp device.
///
/// `inbound` is the staging queue the [`super::driver`] fills from the inbound
/// packet channel immediately before each `poll`; smoltcp drains it via
/// `receive`. `outbound` is where smoltcp hands us packets to emit.
pub struct ChannelDevice {
    pub(crate) inbound: VecDeque<Vec<u8>>,
    outbound: Sender<Vec<u8>>,
    /// Outbound slots a packet the stack originates must leave free, so the
    /// one reply smoltcp may owe a received packet always finds a slot and a
    /// full queue of outgoing data never stops inbound processing.
    reply_slots: usize,
    /// Free outbound slots to wait for after a refusal before polling again,
    /// so a draining queue wakes the driver once per batch, not per packet.
    resume_slots: usize,
    /// The last attempt to take an outbound slot found none.
    outbound_full: bool,
    mtu: usize,
    verify_rx_checksums: bool,
}

impl ChannelDevice {
    pub fn new(outbound: Sender<Vec<u8>>, mtu: usize, verify_rx_checksums: bool) -> Self {
        let capacity = outbound.max_capacity();
        let reply_slots = usize::from(capacity > 1);
        Self {
            inbound: VecDeque::new(),
            outbound,
            reply_slots,
            resume_slots: (capacity / 2).max(reply_slots + 1),
            outbound_full: false,
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

    /// Whether the stack is waiting for outbound queue space: the last poll
    /// was refused a slot, so it holds data or staged inbound packets.
    pub fn outbound_full(&self) -> bool {
        self.outbound_full
    }

    /// Wait until the outbound queue has drained to `resume_slots` free slots,
    /// or has closed. The reservation is level-triggered: room that freed
    /// before this is polled completes it at once, so no drain is missed.
    pub async fn outbound_room(&mut self) {
        let _ = self.outbound.reserve_many(self.resume_slots).await;
        self.outbound_full = false;
    }
}

/// Reserve one outbound slot, leaving `keep_free` slots behind it. A closed
/// queue still yields a token, which discards its packet: the far side is
/// gone, and the stack's timers must keep running to tear its sockets down.
fn take_slot<'a>(
    outbound: &'a Sender<Vec<u8>>,
    keep_free: usize,
    outbound_full: &mut bool,
) -> Option<TxToken<'a>> {
    match outbound.try_reserve() {
        Ok(permit) if outbound.capacity() >= keep_free => {
            *outbound_full = false;
            Some(TxToken {
                permit: Some(permit),
            })
        }
        Ok(_) | Err(TrySendError::Full(())) => {
            *outbound_full = true;
            None
        }
        Err(TrySendError::Closed(())) => {
            *outbound_full = false;
            Some(TxToken { permit: None })
        }
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

    /// smoltcp may answer a received packet at once (an immediate ACK, a
    /// RST) and assumes it can always send that one reply. A packet is handed
    /// over only with its reply slot reserved; without one it stays staged,
    /// intact, until the queue drains.
    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.inbound.is_empty() {
            return None;
        }
        let tx = take_slot(&self.outbound, 0, &mut self.outbound_full)?;
        let buffer = self.inbound.pop_front()?;
        Some((RxToken { buffer }, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        take_slot(&self.outbound, self.reply_slots, &mut self.outbound_full)
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

/// One reserved outbound packet slot. smoltcp serializes a packet into the
/// buffer; on consume we send it with the reservation, which cannot fail. A
/// token without a reservation exists only once the receiver is gone, and
/// drops its packet. An unused token releases its slot.
pub struct TxToken<'a> {
    permit: Option<Permit<'a, Vec<u8>>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        log_tcp_packet("outbound", &buffer);
        match self.permit {
            Some(permit) => permit.send(buffer),
            None => tracing::debug!(
                "rust userspace netstack dropped outbound packet for a closed queue"
            ),
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
    use std::time::Duration;

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

    fn send(token: TxToken<'_>) {
        phy::TxToken::consume(token, 20, |buffer| buffer.fill(0x45));
    }

    #[test]
    fn a_full_outbound_queue_refuses_tokens_and_keeps_inbound_staged() {
        let (outbound, mut packets) = tokio::sync::mpsc::channel(4);
        let mut device = ChannelDevice::new(outbound, 1500, true);
        let now = Instant::from_millis(0);

        for _ in 0..3 {
            send(device.transmit(now).expect("a free outbound slot"));
        }
        assert!(
            device.transmit(now).is_none(),
            "the last slot is kept for a reply to a received packet"
        );
        assert!(device.outbound_full());

        assert!(device.push_inbound(vec![0x45; 20]));
        let (_rx, tx) = device.receive(now).expect("the reply slot");
        send(tx);
        assert!(device.push_inbound(vec![0x45; 20]));
        assert!(
            device.receive(now).is_none(),
            "a received packet waits while no reply slot is free"
        );
        assert!(device.has_inbound(), "the waiting packet stays staged");

        for _ in 0..4 {
            assert_eq!(packets.try_recv().expect("sent packet"), vec![0x45; 20]);
        }
        assert!(device.receive(now).is_some());
        assert!(!device.outbound_full());
    }

    #[test]
    fn a_closed_outbound_queue_discards_instead_of_refusing() {
        let (outbound, packets) = tokio::sync::mpsc::channel(2);
        let mut device = ChannelDevice::new(outbound, 1500, true);
        drop(packets);
        let now = Instant::from_millis(0);
        for _ in 0..4 {
            send(device.transmit(now).expect("a discarding token"));
        }
        assert!(!device.outbound_full());
    }

    #[tokio::test]
    async fn outbound_room_waits_for_half_the_queue_to_drain() {
        let (outbound, mut packets) = tokio::sync::mpsc::channel(8);
        let mut device = ChannelDevice::new(outbound, 1500, true);
        let now = Instant::from_millis(0);
        while let Some(token) = device.transmit(now) {
            send(token);
        }
        assert!(device.outbound_full());

        for _ in 0..2 {
            packets.try_recv().expect("sent packet");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), device.outbound_room())
                .await
                .is_err(),
            "three free slots of eight must not wake the driver"
        );
        packets.try_recv().expect("sent packet");
        tokio::time::timeout(Duration::from_secs(5), device.outbound_room())
            .await
            .expect("four free slots of eight wake the driver");
        assert!(!device.outbound_full());
    }
}
