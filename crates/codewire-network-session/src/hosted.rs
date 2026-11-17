//! The fixed shape of a hosted sandbox's egress path (#4000 P4), shared by
//! the init container that creates it, the daemon that attaches it and the
//! Pod template that points at it. The interface is recorded on #4000.
//!
//! The addresses are a local VM's own: they exist only inside the sandbox,
//! where the netstack at the gateway address answers DNS.

use std::net::Ipv4Addr;

pub mod hello;
pub mod key;

/// The guest's TUN device.
pub const HOSTED_TUN_NAME: &str = "cwegress0";
/// The guest's address on the TUN, a /30 with the netstack.
pub const HOSTED_GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub const HOSTED_PREFIX_LEN: u8 = 30;
/// The netstack's address: the default route and the only DNS resolver.
pub const HOSTED_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// The TUN's MTU, inside [`crate::SessionLimits::HOSTED`]'s bound.
pub const HOSTED_TUN_MTU: usize = 65_000;
/// The daemon's direct tailnet socket, whose traffic leaves over the Pod's
/// own interface rather than the TUN.
pub const TAILNET_DIRECT_SOURCE_PORT: u16 = 31_000;

const _: () = assert!(HOSTED_TUN_MTU == crate::SessionLimits::HOSTED_MTU);
