//! The egress broker's Seatbelt profile (#4000). The Seatbelt core is
//! `codewire-confinement`'s.

use std::ffi::CStr;
use std::io;

/// The general egress broker's profile: everything is denied except dialing
/// TCP to any address and the broker's own DNS. Hickory binds its own UDP
/// port, sends each query to port 53 and receives the reply unconnected, so
/// it needs a UDP bind and inbound UDP; Seatbelt matches inbound datagrams
/// only by their local address. TCP to port 53 (the truncation fallback) is
/// ordinary outbound TCP. Files, processes, signals, Mach services, Unix
/// sockets, TCP listeners and UDP to any other port are refused. The egress
/// policy, not this profile, decides which destinations the broker dials.
const EGRESS_BROKER_PROFILE: &CStr = c"(version 1)(deny default)\
(allow network-outbound (remote tcp \"*:*\"))\
(allow network-outbound (remote udp \"*:53\"))\
(allow network-bind (local udp \"*:*\"))\
(allow network-inbound (local udp \"*:*\"))";

/// Irreversibly confine the egress broker to outbound TCP and its own DNS.
/// Its Seatbelt tests are `codewire-local-vmm`'s (`darwin::sandbox::tests`),
/// which has the close-on-exec sweep their confined children need (#4654).
pub fn confine_egress_broker() -> io::Result<()> {
    codewire_confinement::darwin::apply_profile(EGRESS_BROKER_PROFILE)
}
