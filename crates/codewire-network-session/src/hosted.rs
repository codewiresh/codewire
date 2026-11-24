//! The fixed shape of a hosted sandbox's egress path (#4000 P4), shared by
//! the init container that creates it, the daemon that attaches it and the
//! Pod template that points at it. The interface is recorded on #4000.
//!
//! The addresses are a local VM's own: they exist only inside the sandbox,
//! where the netstack at the gateway address answers DNS.

use std::net::Ipv4Addr;

pub mod hello;
pub mod key;
#[cfg(target_os = "linux")]
pub mod pod_interface;
#[cfg(all(target_os = "linux", feature = "hosted-routing"))]
pub mod routing;

/// The guest's TUN device.
pub const HOSTED_TUN_NAME: &str = "cwegress0";
/// The guest's address on the TUN, a /30 with the netstack.
pub const HOSTED_GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub const HOSTED_PREFIX_LEN: u8 = 30;
/// The netstack's address: the default route and the only DNS resolver.
pub const HOSTED_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// A broker-mode standard guest's `eth0` (#5602): its `cwegress0` holds the
/// /30 above, so `eth0` and the Pod runtime's network worker take the next
/// one. The worker's session accepts packets from this address alone.
pub const HOSTED_BROKER_POD_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 6);
/// That guest's gateway on `eth0`: the Pod runtime's network worker.
pub const HOSTED_BROKER_POD_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
/// The TUN's MTU, inside [`crate::SessionLimits::HOSTED`]'s bound.
pub const HOSTED_TUN_MTU: usize = 65_000;
/// The daemon's direct tailnet socket, whose traffic leaves over the Pod's
/// own interface rather than the TUN.
pub const TAILNET_DIRECT_SOURCE_PORT: u16 = 31_000;
/// The Pod's own interface: the only way out that isn't the TUN, for the
/// daemon's platform dials ([`pod_interface`]) and its direct tailnet socket.
pub const HOSTED_POD_INTERFACE: &str = "eth0";
/// The routing table whose default leaves by the Pod's interface.
pub const HOSTED_POD_ROUTE_TABLE: u32 = 1_000;
/// The priorities of the three rules into that table, ahead of the main
/// table's (32766): source port 31000, output interface eth0, and eth0's own
/// address as source.
pub const HOSTED_POD_RULE_PRIORITIES: [u32; 3] = [1_000, 1_001, 1_002];
/// The network session generation of every hosted stream: a re-placed
/// Sandbox is a new Pod with a new UID, which keys the stream, so nothing
/// counts boots.
pub const HOSTED_GENERATION: u64 = 1;

const _: () = assert!(HOSTED_TUN_MTU == crate::SessionLimits::HOSTED_MTU);
