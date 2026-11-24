//! Guest UDP the worker does not carry (#3997). Only a DNS A or AAAA question
//! to the worker's own resolver is carried. Every other well-formed,
//! unfragmented IPv4 datagram from the guest is dropped, with no reply, and
//! reported to the broker, which records it as refused (`udp_not_carried`)
//! against its destination address and port, folded as it folds a refused
//! dial (SPEC "Networking and egress").
//!
//! ICMP, IPv6, and malformed or fragmented packets are still dropped with no
//! record: recording them is outside what the refusal log promises.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use codewire_netstack::parse_canonical_ipv4_udp_datagram;
use tokio::task::{Id, JoinSet};

use super::{EgressBroker, GUEST_IP};

/// Reports in flight at once, so a datagram flood spawns no more tasks than
/// this. A report shares the broker's admission session with every TCP
/// admission, but is best effort: the IPC client drops it unsent unless the
/// session is idle, so it never waits for the session or delays one.
pub(super) const MAX_UDP_REFUSALS_IN_FLIGHT: usize = 32;

/// The reports in flight, one per destination: a datagram to a destination
/// whose report is still in flight, or past the bound, is dropped
/// unreported, as a retransmitted SYN is while its dial runs. The broker
/// folds what does arrive into one row per destination and port, within
/// its record limits.
#[derive(Default)]
pub(super) struct UdpRefusals {
    reports: JoinSet<()>,
    destinations: HashMap<Id, SocketAddr>,
}

impl UdpRefusals {
    /// Drops `packet`, which is neither admitted DNS nor TCP, and reports it
    /// when it is a guest datagram.
    pub(super) fn refuse<B: EgressBroker>(&mut self, packet: &[u8], broker: &Arc<B>) {
        while let Some(reported) = self.reports.try_join_next_with_id() {
            let id = match reported {
                Ok((id, ())) => id,
                Err(error) => error.id(),
            };
            self.destinations.remove(&id);
        }
        let Ok(datagram) = parse_canonical_ipv4_udp_datagram(packet) else {
            return;
        };
        let destination = datagram.destination;
        if datagram.source.ip() != IpAddr::V4(GUEST_IP)
            || self.destinations.len() >= MAX_UDP_REFUSALS_IN_FLIGHT
            || self
                .destinations
                .values()
                .any(|known| *known == destination)
        {
            return;
        }
        let broker = Arc::clone(broker);
        let report = self.reports.spawn(async move {
            // A report that fails costs only its row: the datagram is
            // dropped either way.
            let _ = broker.refuse_udp(destination).await;
        });
        self.destinations.insert(report.id(), destination);
    }
}
