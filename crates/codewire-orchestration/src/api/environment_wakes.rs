//! One process-wide `LISTEN environment_wakes` (#5529,
//! `docs/dev/IDLE-STOP.md`, "Suspend"): the coordinator asks for a
//! suspended Sandbox's wake when it authorizes a hello naming it, and this
//! process opens a connection to the Sandbox's daemon on 7777, which the
//! Pod's runtime takes as a wake. Nothing passes on it: the connection only
//! has to be accepted.
//!
//! Any role that can reach the database can send on the channel, so a
//! payload only names an environment: where to connect comes from that
//! environment's row alone, and the listener is bounded as a whole. Wakes
//! are queued up to [`QUEUE`] and dropped, counted, beyond it; at most
//! [`REREADS_PER_SECOND`] rows are read a second; and one Sandbox is woken
//! at most every [`WAKE_INTERVAL`]. A listener that reconnects can miss a
//! wake; the client's next use wakes the Sandbox then.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use codewire_server_core::environment_wake::CHANNEL;
use prometheus::{IntCounter, register_int_counter};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::sandbox::template::{WORKSPACE_DAEMON_PORT, workspace_daemon_service_name};

const LISTENER_RETRY: Duration = Duration::from_secs(1);
/// Wakes waiting for a reread; more are dropped.
pub(crate) const QUEUE: usize = 256;
/// Rows reread a second, at most.
pub(crate) const REREADS_PER_SECOND: u32 = 50;
/// One Sandbox is woken at most this often, however many hellos ask.
pub(crate) const WAKE_INTERVAL: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Environment ids are canonical UUIDs; anything longer is not one.
const MAX_PAYLOAD_BYTES: usize = 64;

static DROPPED: OnceLock<IntCounter> = OnceLock::new();

fn dropped() -> &'static IntCounter {
    DROPPED.get_or_init(|| {
        register_int_counter!(
            "codewire_environment_wakes_dropped_total",
            "Wake requests dropped because the queue was full."
        )
        .expect("environment wake metric registration must be unique")
    })
}

/// What became of one notification.
#[derive(Debug, PartialEq, Eq)]
enum Enqueued {
    Queued,
    /// The queue was full: dropped and counted.
    Dropped,
    /// Not an environment id.
    Ignored,
}

fn enqueue(queue: &mpsc::Sender<String>, payload: &str) -> Enqueued {
    let Some(environment_id) = environment_id(payload) else {
        return Enqueued::Ignored;
    };
    match queue.try_send(environment_id) {
        Ok(()) => Enqueued::Queued,
        Err(_) => {
            dropped().inc();
            Enqueued::Dropped
        }
    }
}

/// Runs the process-wide listener on `pool`, reconnecting after failures,
/// and the bounded worker that rereads and wakes.
pub fn spawn_environment_wake_listener(pool: PgPool) -> tokio::task::JoinHandle<()> {
    let (queue, waiting) = mpsc::channel(QUEUE);
    tokio::spawn(work(pool.clone(), waiting));
    tokio::spawn(async move {
        loop {
            if let Err(error) = listen(&pool, &queue).await {
                tracing::warn!(error = %error, "environment wake listener failed");
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    })
}

async fn listen(pool: &PgPool, queue: &mpsc::Sender<String>) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    loop {
        let Some(notification) = listener.try_recv().await? else {
            anyhow::bail!("environment wake listener connection lost");
        };
        enqueue(queue, notification.payload());
    }
}

/// Rereads each queued Sandbox's row, at most [`REREADS_PER_SECOND`], and
/// wakes the ones still marked.
async fn work(pool: PgPool, mut waiting: mpsc::Receiver<String>) {
    let mut pace = tokio::time::interval(Duration::from_secs(1) / REREADS_PER_SECOND);
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut woken = Woken::default();
    while let Some(environment_id) = waiting.recv().await {
        if !woken.admit(&environment_id, Instant::now()) {
            continue;
        }
        pace.tick().await;
        let target = match dial_target(&pool, &environment_id).await {
            Ok(Some(target)) => target,
            Ok(None) => continue,
            Err(_) => {
                tracing::warn!(
                    environment_id,
                    "environment wake could not read the sandbox"
                );
                continue;
            }
        };
        tokio::spawn(async move {
            match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&target))
                .await
            {
                Ok(Ok(_)) => tracing::info!(environment_id, "woke a suspended sandbox for a hello"),
                _ => tracing::warn!(
                    environment_id,
                    "environment wake could not reach the daemon"
                ),
            }
        });
    }
}

/// A payload that is one canonical environment id.
fn environment_id(payload: &str) -> Option<String> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    uuid::Uuid::parse_str(payload)
        .ok()
        .map(|id| id.hyphenated().to_string())
        .filter(|id| id == payload)
}

/// When each Sandbox was last woken from here. Entries expire after
/// [`WAKE_INTERVAL`], and at most [`REREADS_PER_SECOND`] are admitted a
/// second, so it holds no more than those of the last interval.
#[derive(Default)]
struct Woken(HashMap<String, Instant>);

impl Woken {
    /// Whether `environment_id` may be woken at `now`; records it if so.
    fn admit(&mut self, environment_id: &str, now: Instant) -> bool {
        self.0
            .retain(|_, at| now.saturating_duration_since(*at) < WAKE_INTERVAL);
        if self.0.contains_key(environment_id) {
            return false;
        }
        self.0.insert(environment_id.to_owned(), now);
        true
    }
}

/// A marked, running Sandbox's id and namespace, from its own row.
#[derive(sqlx::FromRow)]
struct WakeRow {
    id: String,
    namespace: String,
}

/// Where to connect to wake `environment_id`, from its row alone: its
/// daemon's Service in its namespace, only while it is running and marked.
pub(crate) async fn dial_target(
    pool: &PgPool,
    environment_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<WakeRow> = sqlx::query_as(
        "SELECT e.id, b.namespace FROM environments e \
         JOIN sandbox_environment_backend b ON b.environment_id = e.id \
         WHERE e.id = $1 AND e.suspended_at IS NOT NULL AND e.state = 'running'",
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|WakeRow { id, namespace }| {
        format!(
            "{}.{namespace}.svc.cluster.local:{WORKSPACE_DAEMON_PORT}",
            workspace_daemon_service_name(&id)
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_canonical_environment_id_is_taken() {
        let id = "7c41a9e2-5b3d-4f08-9a6e-2d8b1c4f6e93";
        assert_eq!(environment_id(id).as_deref(), Some(id));
        for payload in [
            "",
            "not-an-id",
            "7C41A9E2-5B3D-4F08-9A6E-2D8B1C4F6E93",
            "7c41a9e25b3d4f089a6e2d8b1c4f6e93",
            "7c41a9e2-5b3d-4f08-9a6e-2d8b1c4f6e93.other",
            &"7".repeat(65),
        ] {
            assert_eq!(environment_id(payload), None, "{payload}");
        }
    }

    #[test]
    fn one_sandbox_is_woken_at_most_every_five_seconds_and_old_entries_go() {
        let mut woken = Woken::default();
        let start = Instant::now();
        assert!(woken.admit("a", start));
        assert!(!woken.admit("a", start + Duration::from_secs(4)));
        assert!(woken.admit("b", start + Duration::from_secs(4)));
        assert!(woken.admit("a", start + WAKE_INTERVAL));
        // Distinct ids don't pile up: only the last interval's stay.
        for n in 0..1_000 {
            woken.admit(&format!("id-{n}"), start + Duration::from_secs(10));
        }
        woken.admit("late", start + Duration::from_secs(16));
        assert_eq!(woken.0.len(), 1);
    }

    #[test]
    fn a_full_queue_drops_and_counts_and_a_bad_payload_is_ignored() {
        let (queue, mut waiting) = mpsc::channel::<String>(QUEUE);
        let before = dropped().get();
        let ids: Vec<String> = (0..QUEUE + 10)
            .map(|_| uuid::Uuid::new_v4().hyphenated().to_string())
            .collect();
        let outcomes: Vec<Enqueued> = ids.iter().map(|id| enqueue(&queue, id)).collect();
        assert!(outcomes[..QUEUE].iter().all(|o| *o == Enqueued::Queued));
        assert!(outcomes[QUEUE..].iter().all(|o| *o == Enqueued::Dropped));
        assert_eq!(dropped().get() - before, 10);
        assert_eq!(enqueue(&queue, "not-an-id"), Enqueued::Ignored);
        let mut queued = Vec::new();
        while let Ok(id) = waiting.try_recv() {
            queued.push(id);
        }
        assert_eq!(queued, ids[..QUEUE]);
    }
}
