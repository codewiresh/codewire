//! A tailnet node's address, checked where the node enters and where its
//! environment's session forwards it (#5561; `docs/dev/AUTH-POLICY.md`,
//! "Addresses"). A client chooses its own address, so the coordinator is
//! where one client is kept from taking another's.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use codewire_tailnet::node::{CW_SERVICE_PREFIX, Node, NodePublic, prefix_from_uuid};
use uuid::Uuid;

use super::PeerKind;

/// Nodes refused or left unforwarded by these rules since the coordinator
/// started. Honest clients choose random addresses, so every one is worth
/// reading.
static ADDRESS_REFUSALS: AtomicU64 = AtomicU64::new(0);

/// Why a node's address was refused; its session ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressRefusal {
    /// Not exactly one IPv6 host address under Codewire's prefix.
    Shape,
    /// A client announced its environment's own address.
    EnvironmentsOwn,
    /// An environment announced another address than its id's.
    NotEnvironmentsOwn,
    /// A client's address changed during its session.
    Changed,
}

impl AddressRefusal {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Shape => {
                "a tailnet node carries exactly one IPv6 host address under fd7a:115c:a1e0::/48"
            }
            Self::EnvironmentsOwn => "a client may not announce its environment's address",
            Self::NotEnvironmentsOwn => "an environment announces the address of its id",
            Self::Changed => "a client keeps one address for its session",
        }
    }
}

/// Checks the address of a node a session announced. A client's first
/// address is pinned in `pinned` for the session's life.
pub(crate) fn check(
    kind: PeerKind,
    env_id: Uuid,
    node: &Node,
    pinned: &mut Option<IpAddr>,
) -> Result<(), AddressRefusal> {
    let own = prefix_from_uuid(&env_id);
    if matches!(kind, PeerKind::Sidecar) {
        return if node.addresses == [own] {
            Ok(())
        } else {
            Err(AddressRefusal::NotEnvironmentsOwn)
        };
    }
    let addr = client_address(node)?;
    if addr == own.addr() {
        return Err(AddressRefusal::EnvironmentsOwn);
    }
    match pinned {
        Some(first) if *first != addr => Err(AddressRefusal::Changed),
        Some(_) => Ok(()),
        None => {
            *pinned = Some(addr);
            Ok(())
        }
    }
}

/// The one address a client node may carry.
fn client_address(node: &Node) -> Result<IpAddr, AddressRefusal> {
    let [prefix] = node.addresses.as_slice() else {
        return Err(AddressRefusal::Shape);
    };
    match prefix.addr() {
        IpAddr::V6(addr) if prefix.bits() == 128 && addr.octets()[..6] == CW_SERVICE_PREFIX => {
            Ok(IpAddr::V6(addr))
        }
        _ => Err(AddressRefusal::Shape),
    }
}

/// Logs and counts a node these rules turn away.
pub(crate) fn count_refusal(env_id: Uuid, peer_id: Uuid, holder: Option<Uuid>, why: &str) {
    let total = ADDRESS_REFUSALS.fetch_add(1, Ordering::Relaxed) + 1;
    tracing::warn!(
        %env_id,
        %peer_id,
        holder = ?holder,
        address_refusals = total,
        "coordinator node address refused: {why}"
    );
}

/// Which client node holds each address an environment's session forwards.
#[derive(Default)]
pub(crate) struct AddressHolders {
    holders: HashMap<IpAddr, Holder>,
}

struct Holder {
    peer_id: Uuid,
    key: NodePublic,
}

impl AddressHolders {
    /// The client nodes this environment's session may forward. The first
    /// live holder of an address keeps it; a node with the same key replaces
    /// it, since a key is bound to one user (#5120) and a reconnect's node
    /// can arrive before the old one's removal. A node from a replica that
    /// predates these checks is checked here too.
    pub(crate) fn admit(&mut self, env_id: Uuid, nodes: Vec<Node>) -> Vec<Node> {
        nodes
            .into_iter()
            .filter(|node| self.admit_node(env_id, node))
            .collect()
    }

    fn admit_node(&mut self, env_id: Uuid, node: &Node) -> bool {
        let addr = match check(PeerKind::Client, env_id, node, &mut None) {
            Ok(()) => client_address(node).ok(),
            Err(refusal) => {
                count_refusal(env_id, node.id, None, refusal.message());
                None
            }
        };
        let Some(addr) = addr else {
            return false;
        };
        match self.holders.get_mut(&addr) {
            Some(holder) if holder.peer_id == node.id || holder.key == node.key => {
                holder.peer_id = node.id;
                holder.key = node.key;
                true
            }
            Some(holder) => {
                count_refusal(
                    env_id,
                    node.id,
                    Some(holder.peer_id),
                    "another client holds this address",
                );
                false
            }
            None => {
                self.holders.insert(
                    addr,
                    Holder {
                        peer_id: node.id,
                        key: node.key,
                    },
                );
                true
            }
        }
    }

    /// Releases what `peer_id` held, on any of its removals.
    pub(crate) fn release(&mut self, peer_id: Uuid) {
        self.holders.retain(|_, holder| holder.peer_id != peer_id);
    }
}

#[cfg(test)]
mod tests;
