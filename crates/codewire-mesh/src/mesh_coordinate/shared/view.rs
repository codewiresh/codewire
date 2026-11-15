//! The replica's view of the other replicas: the watcher, and the registry
//! changes it and the writer make.

use super::*;
use crate::mesh_coordinate::{CoordinateEvent, remove_tunnels, send_updates, tunnel_updates};

/// The replica's watcher: the bucket's current state, then every change.
/// After a failure it starts again, and the new snapshot replaces the view.
pub(super) async fn watch(state: MeshCoordinateState, shared: Arc<Shared>) {
    loop {
        if let Err(error) = watch_once(&state, &shared).await {
            tracing::warn!(%error, "Mesh lost its watch of shared sessions");
        }
        shared.synced.store(false, Ordering::Release);
        tokio::time::sleep(WATCH_RETRY).await;
    }
}

/// One watch, until it fails. The view is synced once the snapshot is in:
/// at the first entry with nothing pending, or at once for an empty bucket.
/// If every message counted by `status` expires before the watch starts, no
/// entry arrives and the view stays unsynced until the next write, at most
/// one refresh later; it fails closed meanwhile.
async fn watch_once(state: &MeshCoordinateState, shared: &Shared) -> Result<(), CoordinationError> {
    // Fresh stream info: `Store::status` returns what was cached when the
    // bucket was opened, so a watch restarted after the first write would
    // take a full bucket for an empty one and its replays for live entries.
    let empty = shared
        .kv
        .stream
        .get_info()
        .await
        .map_err(CoordinationError::unavailable)?
        .state
        .messages
        == 0;
    let mut entries = shared
        .kv
        .watch_with_history(">")
        .await
        .map_err(CoordinationError::unavailable)?;
    let mut seen = Some(HashSet::new());
    if empty {
        state.end_snapshot(HashSet::new());
        seen = None;
        shared.synced.store(true, Ordering::Release);
        shared.beat_after_snapshot();
    }
    while let Some(entry) = entries.next().await {
        let entry = entry.map_err(CoordinationError::unavailable)?;
        #[cfg(test)]
        if shared.watch_paused.load(Ordering::Acquire) {
            continue;
        }
        // A snapshot replays each key's latest entry, old ones included: a
        // replayed heartbeat says nothing about the watch being live now or
        // about the server's clock now.
        let replayed = seen.is_some();
        // The test hook ends the watch on this entry, which it drops unseen:
        // the restarted watch's snapshot delivers it again.
        #[cfg(test)]
        if shared.restart_watch.swap(false, Ordering::AcqRel) {
            return Err(CoordinationError::WatchEnded);
        }
        if let Some(seen) = seen.as_mut() {
            seen.insert(entry.key.clone());
        }
        let written = server_time(entry.created.unix_timestamp(), entry.created.nanosecond());
        match change(
            &entry.key,
            entry.operation,
            &entry.value,
            entry.revision,
            written,
        ) {
            Some(Change::Heartbeat {
                replica_id,
                written,
            }) if replica_id == shared.replica_id() => {
                if replayed {
                    #[cfg(test)]
                    shared
                        .replayed_heartbeats
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                } else {
                    shared.heard_self(written);
                }
            }
            Some(change) => state.apply(change),
            None => {}
        }
        if entry.seen_current
            && let Some(seen) = seen.take()
        {
            state.end_snapshot(seen);
            shared.synced.store(true, Ordering::Release);
            shared.beat_after_snapshot();
        }
    }
    Err(CoordinationError::WatchEnded)
}

impl MeshCoordinateState {
    /// Ends this replica's session of a node whose newer session another
    /// replica holds. Its partners hear nothing: the newer session's record
    /// updates them, and they never see the node removed. The record is the
    /// newer session's, so it stays.
    pub(in crate::mesh_coordinate) fn end_moved(&self, peer_id: Uuid, session_id: Uuid) {
        let (network_id, edges) = {
            let mut registry = self.registry();
            if registry
                .peers
                .get(&peer_id)
                .is_none_or(|peer| peer.session_id != session_id)
            {
                return;
            }
            let Some(peer) = registry.peers.remove(&peer_id) else {
                return;
            };
            peer.close.notify_one();
            // Its subscriptions are the newer session's to make again.
            let edges = registry
                .tunnels
                .iter()
                .filter(|(dial, _)| *dial == peer_id)
                .copied()
                .collect::<Vec<_>>();
            for edge in &edges {
                registry.tunnels.remove(edge);
            }
            (peer.network_id, edges)
        };
        self.dirty_edges(&edges, &network_id);
    }

    /// Ends this replica's session of a node whose record was deleted: it was
    /// revoked on another replica.
    pub(in crate::mesh_coordinate) fn end_revoked(&self, peer_id: Uuid, session_id: Uuid) {
        self.end_session(peer_id, |peer| peer.session_id == session_id);
    }

    /// Shares this registry with the other replicas through NATS, reached in
    /// the background (#3542): the replica serves its own sessions until then.
    pub(crate) fn share_in_background(
        &mut self,
        nats: crate::config::NatsConfig,
    ) -> tokio::task::JoinHandle<()> {
        self.shared_configured = true;
        Shared::start_in_background(self.clone(), nats)
    }

    /// Ends every local session for a replica that is stopping, after marking
    /// their records draining: each node reconnects to another replica, whose
    /// newer record replaces this one's, so partners see the node updated,
    /// never removed (#3542). Records of nodes that don't come back within
    /// [`shared::DRAINING_GRACE`] are dropped.
    pub(crate) async fn drain(&self) {
        if let Some(shared) = self.shared.get() {
            shared.drain().await;
        }
        let closes = {
            let mut registry = self.registry();
            registry.tunnels.clear();
            registry
                .peers
                .drain()
                .map(|(_, peer)| peer.close)
                .collect::<Vec<_>>()
        };
        for close in closes {
            close.notify_one();
        }
    }

    /// Whether Mesh is configured to share its registry, reached or not.
    pub(crate) fn is_shared(&self) -> bool {
        self.shared_configured
    }

    pub(in crate::mesh_coordinate) fn dirty_peer(&self, peer_id: Uuid, network_id: &str) {
        if let Some(shared) = self.shared.get() {
            shared.send(Dirty::Peer {
                peer_id,
                network_id: network_id.to_owned(),
            });
        }
    }

    pub(in crate::mesh_coordinate) fn dirty_edges(&self, edges: &[(Uuid, Uuid)], network_id: &str) {
        if let Some(shared) = self.shared.get() {
            for (dial, target) in edges {
                shared.send(Dirty::Edge {
                    dial: *dial,
                    target: *target,
                    network_id: network_id.to_owned(),
                });
            }
        }
    }

    /// Every record this replica writes, for the writer's refresh.
    pub(in crate::mesh_coordinate) fn local_records(&self) -> Vec<Dirty> {
        let registry = self.registry();
        let peers = registry.peers.iter().map(|(peer_id, peer)| Dirty::Peer {
            peer_id: *peer_id,
            network_id: peer.network_id.clone(),
        });
        let edges = registry.tunnels.iter().filter_map(|(dial, target)| {
            registry.peers.get(dial).map(|peer| Dirty::Edge {
                dial: *dial,
                target: *target,
                network_id: peer.network_id.clone(),
            })
        });
        peers.chain(edges).collect()
    }

    /// The shared record of this replica's live session of `peer_id`.
    pub(in crate::mesh_coordinate) fn peer_record(
        &self,
        peer_id: Uuid,
        network_id: &str,
        replica_id: Uuid,
    ) -> Option<PeerRecord> {
        let registry = self.registry();
        registry
            .peers
            .get(&peer_id)
            .filter(|peer| peer.network_id == network_id)
            .map(|peer| PeerRecord {
                session_id: peer.session_id,
                replica_id,
                network_id: peer.network_id.clone(),
                node: peer.node.clone(),
                last_heard: peer.last_heard,
                draining: false,
                age_ms: u64::try_from(peer.registered.elapsed().as_millis()).unwrap_or(u64::MAX),
            })
    }

    /// The dial's session, while this replica holds the subscription.
    pub(in crate::mesh_coordinate) fn local_edge(&self, dial: Uuid, target: Uuid) -> Option<Uuid> {
        let registry = self.registry();
        registry
            .tunnels
            .contains(&(dial, target))
            .then(|| registry.peers.get(&dial).map(|peer| peer.session_id))
            .flatten()
    }

    /// Records the revision this session's record was written at. Only the
    /// writer's own successful write restarts the session's sharing clock
    /// (`refreshed`); the watch's echo of it doesn't.
    pub(in crate::mesh_coordinate) fn wrote(
        &self,
        peer_id: Uuid,
        session_id: Uuid,
        revision: u64,
        refreshed: bool,
    ) {
        let mut registry = self.registry();
        if let Some(peer) = registry
            .peers
            .get_mut(&peer_id)
            .filter(|peer| peer.session_id == session_id)
        {
            peer.revision = Some(
                peer.revision
                    .map_or(revision, |written| written.max(revision)),
            );
            if refreshed {
                peer.shared_at = tokio::time::Instant::now();
            }
        }
    }

    /// Ends local sessions whose record has not been written for `max_age`:
    /// while the bucket is unreachable, no replica could see a revocation of
    /// them, so they fail closed.
    pub(in crate::mesh_coordinate) fn end_unshared(&self, max_age: Duration) {
        let stale = {
            let registry = self.registry();
            registry
                .peers
                .iter()
                .filter(|(_, peer)| peer.shared_at.elapsed() > max_age)
                .map(|(peer_id, peer)| (*peer_id, peer.session_id))
                .collect::<Vec<_>>()
        };
        for (peer_id, session_id) in stale {
            tracing::warn!(%peer_id, "Mesh ended a session it could not share");
            self.end_session(peer_id, |peer| peer.session_id == session_id);
        }
    }

    /// Drops remote records past their bound, for when no delete or expiry
    /// is seen in time: a stopped replica's draining records go after
    /// [`shared::DRAINING_GRACE`].
    pub(in crate::mesh_coordinate) fn sweep_remote(&self, timing: &Timing) {
        let now = Utc::now();
        let stale = {
            let registry = self.registry();
            registry
                .remote
                .peers
                .iter()
                .filter(|(_, peer)| !peer.fresh(timing, now))
                .map(|(peer_id, _)| *peer_id)
                .collect::<Vec<_>>()
        };
        for peer_id in stale {
            self.drop_remote(peer_id);
        }
    }

    /// This replica's sessions, for the store recheck: peer, session,
    /// network and node name (none for a dial session).
    pub(in crate::mesh_coordinate) fn local_sessions(
        &self,
    ) -> Vec<(Uuid, Uuid, String, Option<String>)> {
        let registry = self.registry();
        registry
            .peers
            .iter()
            .map(|(peer_id, peer)| {
                (
                    *peer_id,
                    peer.session_id,
                    peer.network_id.clone(),
                    peer.node_name.clone(),
                )
            })
            .collect()
    }

    /// Applies one watched change to the remote view.
    pub(in crate::mesh_coordinate) fn apply(&self, change: Change) {
        let Some(shared) = self.shared.get() else {
            return;
        };
        let me = shared.replica_id();
        match change {
            Change::Peer {
                peer_id,
                revision,
                written,
                record: Some(record),
                ..
            } => self.apply_peer(me, peer_id, revision, written, *record),
            Change::Peer {
                peer_id,
                revision,
                record: None,
                expired,
                ..
            } => self.apply_peer_gone(peer_id, revision, expired),
            Change::Edge {
                dial,
                target,
                record: Some(record),
            } => {
                if record.replica_id == me {
                    return;
                }
                let updates = {
                    let mut registry = self.registry();
                    registry
                        .remote
                        .tunnels
                        .insert((dial, target), record.network_id);
                    tunnel_updates(&registry, dial, self.view_current())
                };
                send_updates(dial, updates);
            }
            Change::Edge {
                dial,
                target,
                record: None,
            } => {
                self.registry().remote.tunnels.remove(&(dial, target));
            }
            Change::Retired { net, live: true } => {
                let networks = {
                    let mut registry = self.registry();
                    registry.remote.retired.insert(net.clone());
                    registry
                        .peers
                        .values()
                        .filter(|peer| net_key(&peer.network_id) == net)
                        .map(|peer| peer.network_id.clone())
                        .collect::<HashSet<_>>()
                };
                for network_id in networks {
                    self.retire_locally(&network_id);
                }
            }
            // Handled by the watcher, which knows a replay from a live one.
            Change::Heartbeat { .. } => {}
            Change::Retired { net, live: false } => {
                self.registry().remote.retired.remove(&net);
            }
        }
    }

    /// A session record was written. This replica's own write only confirms
    /// its revision. Another replica's newer session of a node this replica
    /// also holds ends the local one. Once the local session is written, a
    /// later revision is the newer session: every first write compares
    /// registrations before it overwrites (`Writer::write_peer`). Before
    /// then, the later registration is the newer.
    pub(in crate::mesh_coordinate) fn apply_peer(
        &self,
        me: Uuid,
        peer_id: Uuid,
        revision: u64,
        written: DateTime<Utc>,
        record: PeerRecord,
    ) {
        if record.replica_id == me {
            let mut registry = self.registry();
            registry.remote.peers.remove(&peer_id);
            drop(registry);
            self.wrote(peer_id, record.session_id, revision, false);
            return;
        }
        let server_now = shared_server_now(self);
        let local = {
            let registry = self.registry();
            registry.peers.get(&peer_id).map(|peer| {
                let newer_elsewhere = match (peer.revision, server_now) {
                    (Some(local), _) => local < revision,
                    // Both registrations on the server's clock: the record's
                    // from its write time and age, the local one from the
                    // server's clock now and the session's age.
                    (None, Some(now)) => later(
                        (record.registered(written), record.session_id),
                        (now - age(peer.registered), peer.session_id),
                    ),
                    // No server time yet to compare by: the writer decides
                    // when it writes.
                    (None, None) => false,
                };
                (peer.session_id, newer_elsewhere)
            })
        };
        match local {
            Some((_, false)) => return,
            Some((session_id, true)) => self.end_moved(peer_id, session_id),
            None => {}
        }
        let updates = {
            let mut registry = self.registry();
            registry.remote.peers.insert(
                peer_id,
                RemotePeer {
                    network_id: record.network_id,
                    node: record.node,
                    last_heard: record.last_heard,
                    written,
                    draining: record.draining,
                },
            );
            tunnel_updates(&registry, peer_id, self.view_current())
        };
        send_updates(peer_id, updates);
    }

    /// A session record was deleted or expired. Either, newer than this
    /// replica's write of a local session, ends it: a delete is a
    /// revocation, and an expiry means the record went unwritten for too
    /// long, so it fails closed. Another replica's session is removed for its
    /// partners here.
    pub(in crate::mesh_coordinate) fn apply_peer_gone(
        &self,
        peer_id: Uuid,
        revision: u64,
        expired: bool,
    ) {
        let local = {
            let registry = self.registry();
            registry.peers.get(&peer_id).map(|peer| {
                (
                    peer.session_id,
                    peer.revision.is_some_and(|written| written < revision),
                )
            })
        };
        match local {
            Some((session_id, true)) => {
                tracing::info!(%peer_id, expired, "Mesh ended a session whose record is gone");
                self.end_revoked(peer_id, session_id);
            }
            Some(_) => {}
            None => self.drop_remote(peer_id),
        }
    }

    /// Removes another replica's session from the view and tells its
    /// partners here.
    pub(in crate::mesh_coordinate) fn drop_remote(&self, peer_id: Uuid) {
        let (network_id, updates, edges) = {
            let mut registry = self.registry();
            let Some(peer) = registry.remote.peers.remove(&peer_id) else {
                return;
            };
            let (updates, edges) = remove_tunnels(&mut registry, peer_id);
            (peer.network_id, updates, edges)
        };
        self.dirty_edges(&edges, &network_id);
        for tx in updates {
            // A partner whose queue is full or gone is ending or behind; it
            // learns of the removal from its next session's updates.
            let _ = tx.try_send(CoordinateEvent::Remove(peer_id));
        }
    }

    /// The watch has delivered the bucket's whole current state as `seen`:
    /// anything else in the remote view is gone.
    pub(in crate::mesh_coordinate) fn end_snapshot(&self, seen: HashSet<String>) {
        let (peers, edges, retired) = {
            let registry = self.registry();
            let peers = registry
                .remote
                .peers
                .iter()
                .filter(|(peer_id, peer)| !seen.contains(&peer_key(&peer.network_id, **peer_id)))
                .map(|(peer_id, _)| *peer_id)
                .collect::<Vec<_>>();
            let edges = registry
                .remote
                .tunnels
                .iter()
                .filter(|((dial, target), network_id)| {
                    !seen.contains(&edge_key(network_id, *dial, *target))
                })
                .map(|(edge, _)| *edge)
                .collect::<Vec<_>>();
            let retired = registry
                .remote
                .retired
                .iter()
                .filter(|net| !seen.contains(&format!("x.{net}")))
                .cloned()
                .collect::<Vec<_>>();
            (peers, edges, retired)
        };
        for peer_id in peers {
            self.drop_remote(peer_id);
        }
        let mut registry = self.registry();
        for edge in edges {
            registry.remote.tunnels.remove(&edge);
        }
        for net in retired {
            registry.remote.retired.remove(&net);
        }
    }
}

/// Whether registration `a` is later than `b`; the session id breaks a tie,
/// so two replicas always agree.
pub(in crate::mesh_coordinate) fn later(
    a: (DateTime<Utc>, Uuid),
    b: (DateTime<Utc>, Uuid),
) -> bool {
    a > b
}

fn shared_server_now(state: &MeshCoordinateState) -> Option<DateTime<Utc>> {
    state.shared.get().and_then(|shared| shared.server_now())
}
