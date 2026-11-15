//! One process-wide `LISTEN host_operation`, shared by every host session in
//! this process (#3609, slice 2), as `log_notifications` serves log
//! followers: one database connection however many hosts are attached.
//!
//! A signal only says to look: a session claims its host's pending
//! operations on its own host's signal, on every resync after the listener
//! reconnects, when it falls behind the channel, and on every ping. A missed
//! signal costs at most a ping interval.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;

use super::host_operations::OPERATION_CHANNEL;

/// Signals buffered for the slowest session. One that falls further behind
/// claims at once instead.
const SIGNAL_CAPACITY: usize = 1024;
const LISTENER_RETRY: Duration = Duration::from_secs(1);
/// Host IDs are canonical UUIDs; anything longer is not one.
const MAX_PAYLOAD_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostOperationSignal {
    /// An operation was enqueued for this host.
    Host(Arc<str>),
    /// Signals may have been missed: every session claims.
    Resync,
}

pub struct HostOperationSignals {
    signals: broadcast::Sender<HostOperationSignal>,
}

impl HostOperationSignals {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            signals: broadcast::channel(SIGNAL_CAPACITY).0,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HostOperationSignal> {
        self.signals.subscribe()
    }

    pub(crate) fn notify(&self, host_id: &str) {
        if !host_id.is_empty() && host_id.len() <= MAX_PAYLOAD_BYTES {
            // No receiver simply means no host is attached here.
            let _ = self.signals.send(HostOperationSignal::Host(host_id.into()));
        }
    }

    fn resync(&self) {
        // As above: no receiver, no session to tell.
        let _ = self.signals.send(HostOperationSignal::Resync);
    }
}

/// Runs the process-wide `LISTEN host_operation` loop on `pool`,
/// reconnecting after failures. Every (re)subscription is followed by a
/// resync, since operations enqueued meanwhile sent no signal here.
pub fn spawn_host_operation_listener(
    pool: PgPool,
    signals: Arc<HostOperationSignals>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = listen(&pool, &signals).await {
                tracing::warn!(error = %error, "host operation listener failed");
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    })
}

async fn listen(pool: &PgPool, signals: &HostOperationSignals) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(OPERATION_CHANNEL).await?;
    signals.resync();
    loop {
        // `None` is a lost connection: reconnect here, so the resync above
        // always follows the new subscription.
        let Some(notification) = listener.try_recv().await? else {
            anyhow::bail!("host operation listener connection lost");
        };
        signals.notify(notification.payload());
    }
}
