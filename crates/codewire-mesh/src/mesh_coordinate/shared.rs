//! The live registry shared between Mesh replicas through one NATS JetStream
//! KV bucket (#3542; private-docs `designs/mesh-and-nats-high-availability.md`
//! section 5).
//!
//! Each replica writes the records of its own sessions and watches the whole
//! bucket, keeping the other replicas' records as its remote view:
//!
//! | Key | Value | Written by |
//! |---|---|---|
//! | `p.<net>.<peer>` | [`PeerRecord`] | the replica holding the peer's session |
//! | `e.<net>.<dial>.<target>` | [`EdgeRecord`] | the replica holding the dial's session |
//! | `x.<net>` | empty, for [`RETIRED_TTL`] | the replica that deleted the network |
//!
//! `<net>` is a hash of the network id, which is free text. Every record
//! expires [`RECORD_MAX_AGE`] after its last write; a replica rewrites its own
//! every [`REFRESH_INTERVAL`], so only a stopped replica's records expire.
//!
//! **The latest revision of a key wins.** A new session writes its record
//! unconditionally; later writes expect the revision they last wrote. So when
//! another replica writes a newer session of the same node, or a revocation
//! deletes the record, both the watch and the next write tell the older
//! session's replica, which ends it. A revoked record cannot be written back,
//! and a session whose record cannot be written for [`RECORD_MAX_AGE`] ends:
//! an unreachable bucket fails closed.
//!
//! **Order of sessions.** Of two sessions of one node, the later registration
//! is the newer. Registrations are compared on the NATS server's clock: a
//! record carries its session's age by its replica's monotonic clock, so the
//! entry's server-set write time minus that age is when it registered, and a
//! replica places its own unwritten session from the server time its own
//! heartbeat last read live, plus monotonic time since. No replica's wall
//! clock takes part, so skew between replicas and their clock steps can't
//! reorder sessions. A step of the server's own clock, or a new stream leader
//! with another clock, can, until this replica's next heartbeat (at most one
//! refresh) brings its estimate to the new clock. A replica that joins a
//! bucket with records reads its first server time from its first live
//! heartbeat: the guard writes one as soon as the watch's snapshot is in, so
//! that wait is a round trip, not a refresh.
//!
//! **Scale.** Built for the tens to low hundreds of sessions Production has:
//! - the writer writes one record at a time, each call bounded at 2 s, so on
//!   a slow NATS a refresh of about a thousand records outlasts the 45 s view
//!   window (the guard still fails closed on its own clock);
//! - the drain marks records within 3 s, a few hundred on a healthy NATS;
//!   past that the rest expire as after a crash;
//! - `retire_network` scans every key of the bucket once per network delete;
//! - a watch's snapshot holds every key in memory until it is current;
//! - the store recheck asks once per local session every 15 s.
//!
//! **Admission reads only fresh records.** Another replica's session is
//! admitted (DERP, `knows_key`) only while the watch is current and its
//! record's server-set time is within [`RECORD_MAX_AGE`]. A stopping replica
//! marks its records draining: they keep the node for its existing partners
//! for [`DRAINING_GRACE`], admit nothing new, and are then dropped, so a node
//! that reconnects through another replica within that time is updated for
//! its partners, never removed.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_nats::jetstream::kv::{self, CreateErrorKind, Operation};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use codewire_tailnet::node::Node;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::MeshCoordinateState;

pub(crate) const BUCKET: &str = "mesh-sessions";
/// A record not rewritten for this long expires: its replica has stopped.
pub(crate) const RECORD_MAX_AGE: Duration = Duration::from_secs(180);
/// How often a replica rewrites its own records. Faster than the 45 s after
/// which a silent node lists offline, so another replica's `ListNodes` sees a
/// live node's last message at most this old.
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// How long a deleted network refuses sessions authorized before its delete.
/// The store refuses the network's name for good, so this covers only
/// authorizations already in flight.
pub(crate) const RETIRED_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a stopping replica's records keep their nodes for existing
/// partners, from the draining write's server time.
pub(crate) const DRAINING_GRACE: Duration = Duration::from_secs(30);
/// The most a stopping replica spends marking its records draining.
const DRAIN_WRITE_LIMIT: Duration = Duration::from_secs(3);
/// How long the delete markers of expired records stay, for watchers that
/// reconnect meanwhile.
const MARKER_TTL: Duration = Duration::from_secs(60);
const WATCH_RETRY: Duration = Duration::from_secs(2);
/// The most one NATS call of the writer or the guard may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// The view counts as current only while this replica's own heartbeat has
/// come back through the watch within this many refreshes: a watch that
/// stalls without failing stops admitting remote keys.
const VIEW_CURRENT_REFRESHES: u32 = 3;
/// The first wait between attempts to reach NATS at startup, doubling to
/// [`CONNECT_RETRY_MAX`].
const CONNECT_RETRY: Duration = Duration::from_secs(1);
static SHARED_METRIC: std::sync::OnceLock<codewire_server_core::metrics::IntGauge> =
    std::sync::OnceLock::new();

/// How often the sharing gauge is read from the view.
const SHARED_METRIC_INTERVAL: Duration = Duration::from_secs(5);

/// `codewire_mesh_registry_shared` (#5515): 1 while this replica's view of the
/// others is current ([`Shared::view_current`]), 0 otherwise: before NATS is
/// reached, and whenever the watch fails or stalls or the connection drops
/// after that, within [`VIEW_CURRENT_REFRESHES`] refreshes. A replica without
/// NATS registers none, so an alert on 0 fires only where sharing is
/// configured. Readiness never waits for NATS, so this is the only signal.
fn shared_metric() -> &'static codewire_server_core::metrics::IntGauge {
    SHARED_METRIC.get_or_init(|| {
        codewire_server_core::metrics::gauge(
            "codewire_mesh_registry_shared",
            "1 while this Mesh replica's view of the other replicas through NATS is current; 0 before NATS is reached and whenever the view goes stale.",
        )
    })
}

/// Whether this replica shares its registry now: attached, and its view of
/// the other replicas current.
pub(super) fn sharing_now(state: &MeshCoordinateState) -> bool {
    state
        .shared
        .get()
        .is_some_and(|shared| shared.view_current())
}
const CONNECT_RETRY_MAX: Duration = Duration::from_secs(30);

/// The shared registry could not take a change the store has committed. Both
/// steps are idempotent, so a retry finishes the job.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CoordinationError {
    #[error("Mesh is not connected to its shared registry yet")]
    NotConnected,
    #[error("the shared registry refused or timed out the change")]
    Unavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(
        "bucket {BUCKET} exists without delete markers or with another max age; recreate it with this version's settings"
    )]
    BucketConfig,
    #[error("the watch of the shared registry ended")]
    WatchEnded,
}

impl CoordinationError {
    fn unavailable(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The bounds a replica applies; only tests shorten them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    pub refresh: Duration,
    pub record_max_age: Duration,
    pub draining_grace: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            refresh: REFRESH_INTERVAL,
            record_max_age: RECORD_MAX_AGE,
            draining_grace: DRAINING_GRACE,
        }
    }
}

/// One replica's handle on the shared bucket.
pub(crate) struct Shared {
    kv: kv::Store,
    replica_id: Uuid,
    timing: Timing,
    sync: mpsc::UnboundedSender<Dirty>,
    /// Whether the remote view matches the bucket: set once the watch has
    /// delivered the bucket's current state, cleared when the watch fails. A
    /// key in a view that may be stale is never admitted (#2844).
    synced: AtomicBool,
    /// Set while the replica drains: it writes nothing more, so its peers'
    /// records stay for their next session to overwrite.
    stopped: AtomicBool,
    /// When the watch last delivered this replica's own heartbeat.
    heard_self: std::sync::Mutex<Option<tokio::time::Instant>>,
    /// Asks the guard for a heartbeat now: a finished snapshot replays the
    /// last one, which proves nothing, so a live one should follow at once.
    beat_now: tokio::sync::Notify,
    /// The server's clock as last read from this replica's own live
    /// heartbeat, with the monotonic instant it was read at.
    server_clock: std::sync::Mutex<Option<(DateTime<Utc>, tokio::time::Instant)>>,
    /// Added to [`Shared::server_now`], to model a lagging or stepped server
    /// clock.
    #[cfg(test)]
    clock_offset: std::sync::Mutex<chrono::Duration>,
    /// Ends the current watch at its next entry, as a lost connection would.
    #[cfg(test)]
    restart_watch: AtomicBool,
    /// Ignores heartbeat readings, so no server time is known.
    #[cfg(test)]
    ignore_heartbeats: AtomicBool,
    /// How many of this replica's own heartbeats a snapshot replayed.
    #[cfg(test)]
    replayed_heartbeats: std::sync::atomic::AtomicUsize,
    /// Skips the heartbeat a finished snapshot asks for, so a test sees what
    /// the replay alone does.
    #[cfg(test)]
    no_beat_after_snapshot: AtomicBool,
    /// Drops every watched change while set: a watch that stalls.
    #[cfg(test)]
    watch_paused: AtomicBool,
    /// How many of this replica's own heartbeats came back live, ignored or
    /// not: a test's sentinel that the watch has caught up past a point.
    #[cfg(test)]
    live_heartbeats: std::sync::atomic::AtomicUsize,
}

/// What a replica tells its writer: write this local record now, or delete
/// it if it has ended.
pub(super) enum Dirty {
    /// The replica is stopping: mark its records draining, then stop.
    Drain(tokio::sync::oneshot::Sender<()>),
    Peer {
        peer_id: Uuid,
        network_id: String,
    },
    Edge {
        dial: Uuid,
        target: Uuid,
        network_id: String,
    },
    /// A write that hangs until released, for tests.
    #[cfg(test)]
    Hold(tokio::sync::oneshot::Receiver<()>),
    /// Answered once every change queued before it is written, for tests.
    #[cfg(test)]
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl Dirty {
    /// The record a change is about, so a queued batch writes each once.
    fn key(&self) -> Option<String> {
        match self {
            Self::Peer {
                peer_id,
                network_id,
            } => Some(peer_key(network_id, *peer_id)),
            Self::Edge {
                dial,
                target,
                network_id,
            } => Some(edge_key(network_id, *dial, *target)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PeerRecord {
    pub session_id: Uuid,
    pub replica_id: Uuid,
    pub network_id: String,
    pub node: Option<Node>,
    pub last_heard: DateTime<Utc>,
    /// Written once, by a stopping replica (see [`DRAINING_GRACE`]).
    #[serde(default)]
    pub draining: bool,
    /// How long the session had been registered when this was written, by
    /// its replica's monotonic clock. With the entry's server-set time it
    /// places the registration on the NATS server's clock, so of two
    /// sessions of one node the later registration is the newer, whatever
    /// any replica's wall clock says.
    pub age_ms: u64,
}

impl PeerRecord {
    /// When the session registered, on the server's clock, given the server
    /// time this record was written at.
    pub(super) fn registered(&self, written: DateTime<Utc>) -> DateTime<Utc> {
        placed(written, self.age_ms)
    }
}

/// A registration on the server's clock: a server time, less the session's
/// age then.
pub(super) fn placed(at: DateTime<Utc>, age_ms: u64) -> DateTime<Utc> {
    at - chrono::Duration::milliseconds(i64::try_from(age_ms).unwrap_or(i64::MAX))
}

/// How long ago a monotonic instant was.
pub(super) fn age(since: tokio::time::Instant) -> chrono::Duration {
    chrono::Duration::from_std(since.elapsed()).unwrap_or(chrono::Duration::MAX)
}

/// An entry's server-set write time. A missing time is the epoch: as a
/// record's time it counts as stale, never as fresh, and as a registration
/// it is the oldest, so a record without one never beats a session.
pub(super) fn server_time(seconds: i64, nanoseconds: u32) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, nanoseconds).unwrap_or_default()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct EdgeRecord {
    pub replica_id: Uuid,
    pub network_id: String,
}

/// Another replica's session, as its record says.
pub(super) struct RemotePeer {
    pub network_id: String,
    pub node: Option<Node>,
    pub last_heard: DateTime<Utc>,
    /// The record's server-set write time: the writers' clocks never count.
    pub written: DateTime<Utc>,
    pub draining: bool,
}

impl RemotePeer {
    /// Whether this record may still answer for its node: within its bound
    /// of its last write, and for a draining record never for admission.
    pub(super) fn fresh(&self, timing: &Timing, now: DateTime<Utc>) -> bool {
        let bound = if self.draining {
            timing.draining_grace
        } else {
            timing.record_max_age
        };
        now.signed_duration_since(self.written)
            .to_std()
            .map_or(true, |age| age <= bound)
    }
}

/// The other replicas' sessions, subscription edges and deleted networks.
#[derive(Default)]
pub(super) struct Remote {
    pub peers: std::collections::HashMap<Uuid, RemotePeer>,
    /// Each edge with its network id.
    pub tunnels: std::collections::HashMap<(Uuid, Uuid), String>,
    /// Hashed network ids, as in keys.
    pub retired: HashSet<String>,
    /// The bounds remote records are held to.
    pub timing: Timing,
}

/// A watched change to one key.
#[derive(Debug)]
pub(super) enum Change {
    Peer {
        peer_id: Uuid,
        revision: u64,
        /// The entry's server-set time.
        written: DateTime<Utc>,
        /// `None` for a delete or an expiry.
        record: Option<Box<PeerRecord>>,
        /// An expiry rather than a delete.
        expired: bool,
    },
    Edge {
        dial: Uuid,
        target: Uuid,
        /// `None` for a delete or an expiry.
        record: Option<EdgeRecord>,
    },
    Retired {
        net: String,
        live: bool,
    },
    /// A replica's heartbeat: only a replica's own tells it anything, namely
    /// that its watch is live and what the server's clock said.
    Heartbeat {
        replica_id: Uuid,
        written: DateTime<Utc>,
    },
}

/// `<net>` in keys: the first 16 bytes of the network id's SHA-256, in hex.
pub(super) fn net_key(network_id: &str) -> String {
    let sum = Sha256::digest(network_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&sum[..16]);
    Uuid::from_bytes(bytes).simple().to_string()
}

pub(super) fn peer_key(network_id: &str, peer_id: Uuid) -> String {
    format!("p.{}.{}", net_key(network_id), peer_id.simple())
}

pub(super) fn edge_key(network_id: &str, dial: Uuid, target: Uuid) -> String {
    format!(
        "e.{}.{}.{}",
        net_key(network_id),
        dial.simple(),
        target.simple()
    )
}

fn heartbeat_key(replica_id: Uuid) -> String {
    format!("h.{}", replica_id.simple())
}

fn retired_key(network_id: &str) -> String {
    format!("x.{}", net_key(network_id))
}

/// Reads one watched entry. A key or value this version did not write is
/// skipped, never guessed at.
pub(super) fn change(
    key: &str,
    operation: Operation,
    value: &[u8],
    revision: u64,
    written: DateTime<Utc>,
) -> Option<Change> {
    let live = operation == Operation::Put;
    let mut parts = key.split('.');
    let change = match (parts.next()?, parts.next()?, parts.next(), parts.next()) {
        ("p", _net, Some(peer), None) => Change::Peer {
            peer_id: Uuid::try_parse(peer).ok()?,
            revision,
            written,
            record: if live {
                Some(Box::new(serde_json::from_slice(value).ok()?))
            } else {
                None
            },
            expired: operation == Operation::Purge,
        },
        ("e", _net, Some(dial), Some(target)) => Change::Edge {
            dial: Uuid::try_parse(dial).ok()?,
            target: Uuid::try_parse(target).ok()?,
            record: if live {
                Some(serde_json::from_slice(value).ok()?)
            } else {
                None
            },
        },
        ("x", net, None, None) => Change::Retired {
            net: net.to_owned(),
            live,
        },
        ("h", replica, None, None) => Change::Heartbeat {
            replica_id: Uuid::try_parse(replica).ok()?,
            written,
        },
        _ => return None,
    };
    parts.next().is_none().then_some(change)
}

/// The bucket's configuration, replicas from `NATS_KV_REPLICAS`. async-nats
/// turns on `allow_direct` for every KV bucket it creates, so the config has
/// no field for it.
pub(crate) fn bucket_config(replicas: usize) -> kv::Config {
    kv::Config {
        bucket: BUCKET.to_owned(),
        description: "Mesh live sessions shared between replicas (#3542)".to_owned(),
        history: 1,
        max_age: RECORD_MAX_AGE,
        storage: async_nats::jetstream::stream::StorageType::File,
        num_replicas: replicas,
        limit_markers: Some(MARKER_TTL),
        ..Default::default()
    }
}

impl Shared {
    /// Asks the guard for a heartbeat now, once a snapshot is in.
    fn beat_after_snapshot(&self) {
        #[cfg(test)]
        if self.no_beat_after_snapshot.load(Ordering::Acquire) {
            return;
        }
        self.beat_now.notify_one();
    }

    /// Reaches NATS and opens the bucket, retrying until it can, then starts
    /// this replica's writer, watcher and guard. Until then the replica serves
    /// its own sessions and admits no remote key: it fails closed, and its
    /// readiness never waits for NATS. From then on it keeps the sharing
    /// gauge current.
    pub(crate) fn start_in_background(
        state: MeshCoordinateState,
        nats: crate::config::NatsConfig,
    ) -> tokio::task::JoinHandle<()> {
        shared_metric().set(0);
        tokio::spawn(async move {
            let mut wait = CONNECT_RETRY;
            loop {
                match Self::open(&nats).await {
                    Ok(kv) => {
                        Self::attach(&state, kv, Timing::default());
                        tracing::info!(
                            kv_replicas = nats.kv_replicas,
                            "codewire mesh shares its registry"
                        );
                        loop {
                            shared_metric().set(i64::from(sharing_now(&state)));
                            tokio::time::sleep(SHARED_METRIC_INTERVAL).await;
                        }
                    }
                    Err(error) => tracing::warn!(
                        %error,
                        "Mesh can't reach its shared registry yet; it serves its own sessions meanwhile"
                    ),
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(CONNECT_RETRY_MAX);
            }
        })
    }

    async fn open(nats: &crate::config::NatsConfig) -> Result<kv::Store, CoordinationError> {
        let client = codewire_server_core::nats::connect_with_login(
            Some(&nats.url),
            nats.login(),
            nats.token(),
        )
        .await
        .map_err(|error| CoordinationError::Unavailable(error.into()))?
        .ok_or(CoordinationError::NotConnected)?;
        let js = async_nats::jetstream::new(client);
        let mut kv = codewire_server_core::nats::kv_bucket(&js, bucket_config(nats.kv_replicas))
            .await
            .map_err(|error| CoordinationError::Unavailable(error.into()))?;
        // kv_bucket keeps an existing bucket whose update was refused. Without
        // delete markers, expiries are invisible to watchers, so that bucket
        // is refused here rather than used.
        let info = kv
            .stream
            .info()
            .await
            .map_err(CoordinationError::unavailable)?;
        // A bucket kept with another max_age expires records on another
        // bound than the guard and admission assume.
        if info.config.subject_delete_marker_ttl.is_none() || info.config.max_age != RECORD_MAX_AGE
        {
            return Err(CoordinationError::BucketConfig);
        }
        Ok(kv)
    }

    pub(super) fn attach(
        state: &MeshCoordinateState,
        kv: kv::Store,
        timing: Timing,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let (sync, sync_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Self {
            kv,
            replica_id: Uuid::new_v4(),
            timing,
            sync,
            synced: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            heard_self: std::sync::Mutex::new(None),
            beat_now: tokio::sync::Notify::new(),
            server_clock: std::sync::Mutex::new(None),
            #[cfg(test)]
            clock_offset: std::sync::Mutex::new(chrono::Duration::zero()),
            #[cfg(test)]
            restart_watch: AtomicBool::new(false),
            #[cfg(test)]
            ignore_heartbeats: AtomicBool::new(false),
            #[cfg(test)]
            replayed_heartbeats: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            no_beat_after_snapshot: AtomicBool::new(false),
            #[cfg(test)]
            watch_paused: AtomicBool::new(false),
            #[cfg(test)]
            live_heartbeats: std::sync::atomic::AtomicUsize::new(0),
        });
        {
            let mut registry = state.registry();
            registry.remote.timing = timing;
            // Sessions served before NATS was reached haven't been shared
            // yet, not failed to be: their clock starts now, so the guard
            // gives the writer its full bound to write them.
            let now = tokio::time::Instant::now();
            for peer in registry.peers.values_mut() {
                peer.shared_at = now;
            }
        }
        if state.shared.set(shared.clone()).is_err() {
            tracing::warn!("Mesh registry was already shared");
            return Vec::new();
        }
        vec![
            tokio::spawn(write(state.clone(), shared.clone(), sync_rx)),
            tokio::spawn(watch(state.clone(), shared.clone())),
            tokio::spawn(guard(state.clone(), shared)),
        ]
    }

    pub(super) fn replica_id(&self) -> Uuid {
        self.replica_id
    }

    pub(super) fn timing(&self) -> Timing {
        self.timing
    }

    /// Has the writer mark this replica's records draining, after every
    /// write queued before it, then stop. Each is marked only over the
    /// revision this replica last wrote: a newer session's record is never
    /// touched, and a record whose mark fails expires instead.
    pub(super) async fn drain(&self) {
        let (done, finished) = tokio::sync::oneshot::channel();
        // A send fails only once the writer has gone; the reply then never
        // comes, which is reported below.
        let _ = self.sync.send(Dirty::Drain(done));
        self.stop();
        // A dropped reply is as much a failure as the time limit.
        if !matches!(
            tokio::time::timeout(DRAIN_WRITE_LIMIT, finished).await,
            Ok(Ok(()))
        ) {
            tracing::warn!("Mesh could not mark all its records draining; they expire instead");
        }
    }

    /// Whether the remote view may answer for other replicas: the watch has
    /// delivered the bucket's state, and has delivered this replica's own
    /// heartbeat within [`VIEW_CURRENT_REFRESHES`] refreshes.
    pub(super) fn view_current(&self) -> bool {
        let heard = *self
            .heard_self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.synced.load(Ordering::Acquire)
            && heard.is_some_and(|at| at.elapsed() <= self.timing.refresh * VIEW_CURRENT_REFRESHES)
    }

    pub(super) fn send(&self, dirty: Dirty) {
        if !self.stopped.load(Ordering::Acquire) {
            // A send fails only once the writer has gone, while the process
            // stops: the record then expires.
            let _ = self.sync.send(dirty);
        }
    }

    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    /// Deletes a revoked node's record. Its replica ends the session when it
    /// sees the delete, and can no longer write the record back.
    pub(super) async fn delete_peer(
        &self,
        network_id: &str,
        peer_id: Uuid,
    ) -> Result<(), CoordinationError> {
        self.kv
            .delete(peer_key(network_id, peer_id))
            .await
            .map_err(CoordinationError::unavailable)
    }

    /// Marks a deleted network, so every replica ends its sessions and
    /// refuses sessions authorized before the delete, then deletes the
    /// network's peer records.
    pub(super) async fn retire_network(&self, network_id: &str) -> Result<(), CoordinationError> {
        match self
            .kv
            .create_with_ttl(retired_key(network_id), Bytes::new(), RETIRED_TTL)
            .await
        {
            Ok(_) => {}
            Err(error) if error.kind() == CreateErrorKind::AlreadyExists => {}
            Err(error) => return Err(CoordinationError::unavailable(error)),
        }
        let prefix = format!("p.{}.", net_key(network_id));
        let mut keys = self
            .kv
            .keys()
            .await
            .map_err(CoordinationError::unavailable)?;
        while let Some(key) = keys.next().await {
            let key = key.map_err(CoordinationError::unavailable)?;
            if key.starts_with(&prefix) {
                self.kv
                    .delete(key)
                    .await
                    .map_err(CoordinationError::unavailable)?;
            }
        }
        Ok(())
    }

    /// Records that the watch delivered this replica's own heartbeat live,
    /// written at server time `written`, and takes it as the server's clock.
    /// Live heartbeats arrive in order, each late by the watch's delivery lag,
    /// which bounds the estimate's error behind the server's clock. So the
    /// latest reading is the best one, in either direction: a server clock
    /// stepped back, or a new leader behind, is followed at once rather than
    /// left with the estimate ahead. Replays never get here (see
    /// `watch_once`).
    pub(super) fn heard_self(&self, written: DateTime<Utc>) {
        #[cfg(test)]
        self.live_heartbeats.fetch_add(1, Ordering::AcqRel);
        #[cfg(test)]
        if self.ignore_heartbeats.load(Ordering::Acquire) {
            return;
        }
        let now = tokio::time::Instant::now();
        *self
            .heard_self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now);
        let mut clock = self
            .server_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = Some((written, now));
    }

    /// The server's clock now, from the latest live heartbeat reading and the
    /// monotonic time since; `None` before the first. It runs behind by the
    /// heartbeat's delivery delay. A step of the server's clock, either way,
    /// or a new stream leader with another clock, is followed at the next
    /// heartbeat, within one refresh; until then registrations are placed off
    /// by up to the step.
    pub(super) fn server_now(&self) -> Option<DateTime<Utc>> {
        let clock = *self
            .server_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        let clock = clock.map(|(at, read)| {
            let offset = *self
                .clock_offset
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (at + offset, read)
        });
        clock.map(|(at, read)| at + age(read))
    }
}

/// The replica's guard, on its own clock so a slow writer can't delay it:
/// ends local sessions that couldn't be shared in time, drops stale remote
/// records, and writes this replica's heartbeat.
async fn guard(state: MeshCoordinateState, shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(shared.timing.refresh);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = shared.beat_now.notified() => {}
        }
        if shared.stopped.load(Ordering::Acquire) {
            return;
        }
        state.end_unshared(shared.timing.record_max_age);
        state.sweep_remote(&shared.timing);
        let beat = shared
            .kv
            .put(heartbeat_key(shared.replica_id), Bytes::new());
        match tokio::time::timeout(WRITE_TIMEOUT, beat).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(%error, "Mesh could not write its heartbeat"),
            Err(_) => tracing::warn!("Mesh timed out writing its heartbeat"),
        }
    }
}

mod view;
mod writer;

use view::watch;
use writer::write;

#[cfg(test)]
mod tests;
