//! The daemon's tailnet SSH connections, each known by the node key that held
//! its address when it was accepted, so a client the coordinator removes
//! loses them rather than living on until SSH's keepalive gives up (#3586;
//! `docs/dev/AUTH-POLICY.md`, "The environment's side"). A client chooses its
//! own address, so an address alone does not say who a connection belongs to.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use codewire_tailnet::conn::allowed_ips;
use codewire_tailnet::node::{Node, NodePublic, Prefix};
use tokio::sync::watch;
use tokio::time::Instant;

/// How long a connection's key may go without its address before the
/// connection is closed. Peer sets are whole snapshots, so a client's
/// reconnect (#5120) and the daemon's own coordinator session starting again
/// each leave a live client out for a moment; no packet reaches it meanwhile.
pub(crate) const ABSENT_GRACE: Duration = Duration::from_secs(20);

#[derive(Default)]
pub(crate) struct PeerConnections {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Who holds each address in the peer set last applied: the data plane's
    /// own rule, [`allowed_ips`] (a host address, not the daemon's own,
    /// claimed by exactly one node).
    holders: HashMap<IpAddr, NodePublic>,
    next: u64,
    open: HashMap<u64, Open>,
}

struct Open {
    peer: IpAddr,
    key: NodePublic,
    standing: watch::Sender<Standing>,
}

/// Where a connection's key stands with its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    Holds,
    /// No key has held the address since this instant.
    AbsentSince(Instant),
    /// Another key holds the address.
    Taken,
}

impl PeerConnections {
    /// Take `nodes` as the peer set of a daemon whose own addresses are
    /// `own`. A connection whose address another key now holds closes at
    /// once; one whose address no key holds closes once that has lasted
    /// [`ABSENT_GRACE`].
    pub(crate) fn apply(&self, nodes: &[Node], own: &[Prefix]) {
        let mut state = self.lock();
        state.holders = nodes
            .iter()
            .zip(allowed_ips(nodes, own))
            .flat_map(|(node, allowed)| allowed.into_iter().map(|prefix| (prefix.addr(), node.key)))
            .collect();
        let now = Instant::now();
        for open in state.open.values() {
            let standing = match state.holders.get(&open.peer) {
                Some(key) if *key == open.key => Standing::Holds,
                Some(_) => Standing::Taken,
                None => match *open.standing.borrow() {
                    Standing::AbsentSince(since) => Standing::AbsentSince(since),
                    Standing::Holds | Standing::Taken => Standing::AbsentSince(now),
                },
            };
            open.standing.send_if_modified(|current| {
                let changed = *current != standing;
                *current = standing;
                changed
            });
        }
    }

    /// Serve the connection from `peer` until `serve` ends or the peer set
    /// takes the address from its key. It is recorded, with the key holding
    /// `peer`, before `serve` first runs; from an address no single peer
    /// holds, nothing is served. Closing drops `serve`, which ends it as its
    /// client vanishing would.
    pub(crate) async fn serve<F>(&self, peer: IpAddr, serve: F)
    where
        F: Future<Output = ()>,
    {
        let (id, mut standing) = {
            let mut state = self.lock();
            let Some(&key) = state.holders.get(&peer) else {
                tracing::info!(peer = %peer, "tailnet SSH connection refused: no peer holds its address");
                return;
            };
            let id = state.next;
            state.next += 1;
            let (sender, standing) = watch::channel(Standing::Holds);
            state.open.insert(
                id,
                Open {
                    peer,
                    key,
                    standing: sender,
                },
            );
            (id, standing)
        };
        let _registered = Registered {
            connections: self,
            id,
        };
        tokio::pin!(serve);
        loop {
            let current = *standing.borrow_and_update();
            let deadline = match current {
                Standing::Holds => None,
                Standing::AbsentSince(since) => Some(since + ABSENT_GRACE),
                Standing::Taken => {
                    tracing::info!(peer = %peer, "tailnet SSH connection closed: another peer holds its address");
                    return;
                }
            };
            tokio::select! {
                () = &mut serve => return,
                () = absent_until(deadline) => {
                    tracing::info!(peer = %peer, "tailnet SSH connection closed: its peer was removed");
                    return;
                }
                changed = standing.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().open.len()
    }
}

/// Resolves at `deadline`, or never without one.
async fn absent_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Removes a connection's entry however its task ends.
struct Registered<'a> {
    connections: &'a PeerConnections,
    id: u64,
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.connections.lock().open.remove(&self.id);
    }
}

#[cfg(test)]
mod tests;
