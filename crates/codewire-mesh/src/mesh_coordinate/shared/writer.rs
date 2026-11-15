//! The replica's writer: the only task that writes this replica's records.

use super::*;

/// The replica's writer: one task, so writes of one key keep their order.
/// Every [`Timing::refresh`] it rewrites all local records, which also
/// retries any write NATS refused meanwhile. Each NATS call is bounded by
/// [`WRITE_TIMEOUT`], and what is queued is written once per key, so an
/// unreachable bucket slows the writer but never backs it up without bound.
/// Ending sessions that can't be shared is the guard's job, not this one's.
pub(super) async fn write(
    state: MeshCoordinateState,
    shared: Arc<Shared>,
    mut rx: mpsc::UnboundedReceiver<Dirty>,
) {
    let mut writer = Writer {
        state,
        shared,
        written: std::collections::HashMap::new(),
    };
    let mut refresh = tokio::time::interval(writer.shared.timing.refresh);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            // A queued drain wins over a refresh: a stopping replica marks its
            // records draining rather than skipping it.
            biased;
            first = rx.recv() => {
                let Some(first) = first else { return };
                let mut batch = vec![first];
                while let Ok(next) = rx.try_recv() {
                    batch.push(next);
                }
                if writer.apply_batch(batch).await {
                    return;
                }
            }
            _ = refresh.tick() => {
                // A stopping replica refreshes nothing; its queued drain ends
                // the writer.
                if writer.shared.stopped.load(Ordering::Acquire) {
                    continue;
                }
                for dirty in writer.state.local_records() {
                    writer.apply(dirty).await;
                }
            }
        }
    }
}

struct Writer {
    state: MeshCoordinateState,
    shared: Arc<Shared>,
    /// The revision this replica last wrote to each of its keys, and the
    /// session that wrote it.
    written: std::collections::HashMap<String, (Uuid, u64)>,
}

impl Writer {
    /// Writes a batch of queued changes, each key once, in queue order. Returns
    /// true once a drain is done and the writer must stop.
    async fn apply_batch(&mut self, batch: Vec<Dirty>) -> bool {
        let mut seen = std::collections::HashSet::new();
        for dirty in batch {
            match dirty {
                Dirty::Drain(done) => {
                    self.mark_draining().await;
                    // The drain stops waiting at its own limit; nobody may be
                    // listening any more.
                    let _ = done.send(());
                    return true;
                }
                #[cfg(test)]
                Dirty::Hold(release) => {
                    // A write that hangs until the test releases it (or drops
                    // the sender, which ends the wait too).
                    let _ = release.await;
                }
                #[cfg(test)]
                Dirty::Flush(done) => {
                    let _ = done.send(());
                }
                dirty => {
                    if seen.insert(dirty.key()) {
                        self.apply(dirty).await;
                    }
                }
            }
        }
        false
    }

    async fn mark_draining(&mut self) {
        for dirty in self.state.local_records() {
            let Dirty::Peer {
                peer_id,
                network_id,
            } = dirty
            else {
                continue;
            };
            let Some(mut record) =
                self.state
                    .peer_record(peer_id, &network_id, self.shared.replica_id)
            else {
                continue;
            };
            let key = peer_key(&network_id, peer_id);
            let Some(&(_, revision)) = self
                .written
                .get(&key)
                .filter(|(session, _)| *session == record.session_id)
            else {
                continue;
            };
            record.draining = true;
            let Ok(value) = serde_json::to_vec(&record) else {
                continue;
            };
            match bounded(self.shared.kv.update(key, value.into(), revision)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::debug!(%error, "Mesh left a record it no longer owns"),
                Err(_) => tracing::warn!("Mesh timed out marking a record draining"),
            }
        }
    }

    async fn apply(&mut self, dirty: Dirty) {
        match dirty {
            Dirty::Drain(_) => {}
            #[cfg(test)]
            Dirty::Hold(_) | Dirty::Flush(_) => {}
            Dirty::Peer {
                peer_id,
                network_id,
            } => {
                let key = peer_key(&network_id, peer_id);
                match self
                    .state
                    .peer_record(peer_id, &network_id, self.shared.replica_id)
                {
                    Some(record) => self.write_peer(peer_id, key, record).await,
                    None => self.delete(&key).await,
                }
            }
            Dirty::Edge {
                dial,
                target,
                network_id,
            } => {
                let key = edge_key(&network_id, dial, target);
                match self.state.local_edge(dial, target) {
                    Some(session_id) => {
                        let record = EdgeRecord {
                            replica_id: self.shared.replica_id,
                            network_id,
                        };
                        self.write(&key, session_id, &record).await;
                    }
                    None => self.delete(&key).await,
                }
            }
        }
    }

    async fn write_peer(&mut self, peer_id: Uuid, key: String, record: PeerRecord) {
        let session_id = record.session_id;
        let first = !self
            .written
            .get(&key)
            .is_some_and(|(session, _)| *session == session_id);
        let written = if first {
            self.create_peer(&key, &record).await
        } else {
            self.write(&key, session_id, &record).await
        };
        match written {
            Written::Yes(revision) => self.state.wrote(peer_id, session_id, revision, true),
            Written::Superseded => {
                // Someone wrote the key since this replica did: find out who.
                match bounded(self.shared.kv.entry(key.as_str()))
                    .await
                    .unwrap_or_else(|_| Err(kv::EntryError::new(kv::EntryErrorKind::TimedOut)))
                {
                    Ok(Some(entry)) if entry.operation == Operation::Put => {
                        let newer = serde_json::from_slice::<PeerRecord>(&entry.value)
                            .is_ok_and(|other| other.session_id != session_id);
                        if newer {
                            self.written.remove(&key);
                            self.state.end_moved(peer_id, session_id);
                        } else {
                            self.written.insert(key, (session_id, entry.revision));
                        }
                    }
                    // Deleted (revoked) or expired (not refreshed in time):
                    // the session ends rather than writing its record back.
                    Ok(_) => {
                        self.written.remove(&key);
                        self.state.end_revoked(peer_id, session_id);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Mesh could not read a shared session record");
                    }
                }
            }
            Written::No => {}
        }
    }

    /// A session's first write: it creates the record. If the node already has
    /// another session's record, the later registration wins: this session
    /// overwrites an older one's record over the revision it read, or, when
    /// the record is the newer session's, ends (`Superseded`). So a session
    /// whose first write was delayed can't overwrite the newer session a
    /// reconnect made on another replica.
    async fn create_peer(&mut self, key: &str, record: &PeerRecord) -> Written {
        let Ok(value) = serde_json::to_vec(record) else {
            return Written::No;
        };
        let refused = match bounded(self.shared.kv.create(key, value.clone().into())).await {
            Ok(Ok(revision)) => return self.wrote_key(key, record.session_id, revision),
            Ok(Err(error)) if error.kind() == CreateErrorKind::AlreadyExists => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => Some("timed out".to_owned()),
        };
        if let Some(error) = refused {
            tracing::warn!(%error, "Mesh could not create a shared session record");
            return Written::No;
        }
        // The key holds a live record: whose, and is it newer?
        let entry = match bounded(self.shared.kv.entry(key)).await {
            Ok(Ok(Some(entry))) if entry.operation == Operation::Put => entry,
            // Gone again since the create: the next refresh creates it.
            Ok(Ok(_)) => return Written::No,
            Ok(Err(error)) => {
                tracing::warn!(%error, "Mesh could not read a shared session record");
                return Written::No;
            }
            Err(_) => return Written::No,
        };
        let Ok(other) = serde_json::from_slice::<PeerRecord>(&entry.value) else {
            return Written::No;
        };
        if other.session_id == record.session_id {
            return self.wrote_key(key, record.session_id, entry.revision);
        }
        // Both registrations on the server's clock: the other's from its
        // write time and age, this one's from the server's clock now and its
        // age. No replica's wall clock takes part.
        let Some(now) = self.shared.server_now() else {
            // No server time yet: the next refresh decides.
            return Written::No;
        };
        let ours = placed(now, record.age_ms);
        if super::view::later(
            (
                other.registered(server_time(
                    entry.created.unix_timestamp(),
                    entry.created.nanosecond(),
                )),
                other.session_id,
            ),
            (ours, record.session_id),
        ) {
            return Written::Superseded;
        }
        match bounded(self.shared.kv.update(key, value.into(), entry.revision)).await {
            Ok(Ok(revision)) => self.wrote_key(key, record.session_id, revision),
            // Written again meanwhile: the next refresh decides afresh.
            _ => Written::No,
        }
    }

    fn wrote_key(&mut self, key: &str, session_id: Uuid, revision: u64) -> Written {
        self.written.insert(key.to_owned(), (session_id, revision));
        Written::Yes(revision)
    }

    /// Writes `value` to `key` for `session_id`: unconditionally for a key
    /// this session has not written yet, otherwise only over the revision it
    /// last wrote. Session records take [`Self::create_peer`] for their first
    /// write instead.
    async fn write<T: Serialize>(&mut self, key: &str, session_id: Uuid, value: &T) -> Written {
        let Ok(value) = serde_json::to_vec(value) else {
            return Written::No;
        };
        let prior = self
            .written
            .get(key)
            .filter(|(session, _)| *session == session_id)
            .map(|(_, revision)| *revision);
        let result = match prior {
            None => match bounded(self.shared.kv.put(key, value.into())).await {
                Ok(result) => result.map_err(|e| (false, e.to_string())),
                Err(_) => Err((false, "timed out".to_owned())),
            },
            Some(revision) => {
                match bounded(self.shared.kv.update(key, value.into(), revision)).await {
                    Ok(result) => result.map_err(|e| {
                        (
                            e.kind() == kv::UpdateErrorKind::WrongLastRevision,
                            e.to_string(),
                        )
                    }),
                    Err(_) => Err((false, "timed out".to_owned())),
                }
            }
        };
        match result {
            Ok(revision) => {
                self.written.insert(key.to_owned(), (session_id, revision));
                Written::Yes(revision)
            }
            Err((true, _)) => Written::Superseded,
            Err((false, error)) => {
                tracing::warn!(%error, "Mesh could not write a shared session record");
                Written::No
            }
        }
    }

    /// Deletes a record this replica wrote, unless someone has written the
    /// key since: a newer session's record is never deleted.
    async fn delete(&mut self, key: &str) {
        if let Some((_, revision)) = self.written.remove(key) {
            match bounded(self.shared.kv.delete_expect_revision(key, Some(revision))).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%error, "Mesh left a shared record someone else wrote");
                }
                // The record expires instead.
                Err(_) => tracing::warn!("Mesh timed out deleting a shared record"),
            }
        }
    }
}

enum Written {
    Yes(u64),
    /// The key holds a revision this replica did not write.
    Superseded,
    No,
}

/// One NATS call, bounded by [`WRITE_TIMEOUT`].
async fn bounded<T>(
    call: impl std::future::Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
    tokio::time::timeout(WRITE_TIMEOUT, call).await
}
