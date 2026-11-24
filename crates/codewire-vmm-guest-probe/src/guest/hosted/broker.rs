//! A broker-mode standard guest's egress path (#5602, design: comment
//! 130891): before the workload starts, guest init does in the workspace's
//! network namespace what a Kata Pod's init container `cw
//! __hosted-egress-tun` does in the Pod's. It creates the persistent TUN
//! `cwegress0`, owned by the workspace user so the daemon attaches it without
//! privilege, then makes the routing and reads it back with the same library
//! call (`codewire_network_session::hosted::routing::configure`: IPv6 off,
//! the Pod table and its rules for `eth0`, the main default into the TUN). A
//! failure fails the boot: a broker-mode workload never starts on a half-made
//! path.

use super::*;

/// How long the TUN and routing may take, beyond the routing's own bound.
const MAKE_BOUND: Duration = Duration::from_secs(10);

/// Makes `cwegress0` and its routing in the workspace's network namespace,
/// owned by `uid`, and waits until both are made or one fails.
pub(super) fn make_egress_path(uid: u32) -> Result<()> {
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("codewire-hosted-egress-path".to_owned())
        .spawn(move || {
            // The receiver waits for exactly this one message.
            let _ = sent.send(in_workspace_namespace(uid));
        })
        .context("spawn the hosted egress path thread")?;
    received
        .recv_timeout(MAKE_BOUND)
        .context("wait for the hosted egress path")?
}

/// On this thread only: join the workspace's network namespace, then make the
/// TUN and the routing there.
fn in_workspace_namespace(uid: u32) -> Result<()> {
    let namespace = std::fs::File::open(super::super::NETWORK_NAMESPACE_PATH)
        .context("open the workspace network namespace")?;
    // SAFETY: setns on this thread alone, with a descriptor this thread
    // owns; the thread does nothing else after it.
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("join the workspace network namespace");
    }
    crate::tun::create_persistent(codewire_network_session::hosted::HOSTED_TUN_NAME, uid)
        .context("create the egress TUN")?;
    codewire_network_session::hosted::routing::configure().context("make the egress routing")
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    /// Whether `(address/prefix, gateway)` names a gateway beside the address
    /// in its own subnet, never the address itself or a point-to-point link.
    fn gateway_in_own_subnet((address, gateway): (&str, &str)) -> bool {
        let (address, prefix) = address.split_once('/').unwrap();
        let address: Ipv4Addr = address.parse().unwrap();
        let prefix: u32 = prefix.parse().unwrap();
        let gateway: Ipv4Addr = gateway.parse().unwrap();
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        prefix < 32 && gateway != address && u32::from(gateway) & mask == u32::from(address) & mask
    }

    /// The routing takes the Pod table's gateway from `eth0`'s default
    /// route, and fails on a point-to-point one. Each guest's `eth0`, as
    /// `eth0_addresses_for` gives it, has its default via a gateway in its
    /// own subnet (cw-egress's review, #5602): a broker-mode guest's on the
    /// broker /30, every other guest's on the usual one.
    #[test]
    fn each_guests_eth0_default_goes_via_a_gateway_in_its_own_subnet() {
        let base = "console=ttyS0 rdinit=/init panic=-1";
        let broker = super::super::eth0_addresses_for(&format!("{base} codewire.hosted_broker=1"));
        assert_eq!(broker, ("192.0.2.6/30", "192.0.2.5"));
        assert!(gateway_in_own_subnet(broker));
        let carried = super::super::eth0_addresses_for(&format!("{base} codewire.guest_carried=1"));
        assert_eq!(carried, ("192.0.2.2/30", "192.0.2.1"));
        assert!(gateway_in_own_subnet(carried));
        // The check itself refuses a point-to-point or self-gateway pair.
        assert!(!gateway_in_own_subnet(("192.0.2.6/32", "192.0.2.5")));
        assert!(!gateway_in_own_subnet(("192.0.2.6/30", "192.0.2.6")));
        assert!(!gateway_in_own_subnet(("192.0.2.6/30", "192.0.2.1")));
    }
}
