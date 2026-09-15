//! Fixed product-network variant for the unreachable two-VM developer fixture.
//!
//! This module owns only guest-local topology and the finite synthetic TCP
//! endpoint. The existing production broker and worker entrypoints remain the
//! owners of policy, authenticated IPC, descriptor transfer, and packet work.

mod endpoint;
mod topology;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

pub(super) use endpoint::{
    ENDPOINT_CANCEL_MESSAGE, ENDPOINT_COMPLETED_MESSAGE, ENDPOINT_READY_MESSAGE,
    run_inherited_endpoint,
};
pub(super) use topology::prepare_service_topology;

pub(super) const PUBLIC_ADDRESS: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
pub(super) const PUBLIC_PORT: u16 = 443;
pub(super) const PAYLOAD_LEN: usize = 4096;

pub(super) const fn destination() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(PUBLIC_ADDRESS, PUBLIC_PORT))
}

pub(super) fn payload(response: bool) -> [u8; PAYLOAD_LEN] {
    std::array::from_fn(|index| (index as u8) ^ if response { 0x5a } else { 0 })
}

#[cfg(test)]
mod tests;
