//! One process-wide `LISTEN environment_logs`, shared by every StreamLogs
//! follower, plus the per-account bound on concurrent follows.
//!
//! A follower used to open its own PostgreSQL listener connection, so open
//! log views could exhaust database connections for every tenant. Now one
//! listener fans each notification out over a broadcast channel. A follower
//! never relies on a single signal: after a listener reconnect every follower
//! re-reads (`Resync`), and a follower that falls behind the channel re-reads
//! instead of losing rows. The composite-cursor re-read is idempotent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;

pub(crate) const ENVIRONMENT_LOGS_CHANNEL: &str = "environment_logs";
/// Live follows one account may hold at once across this process: CLI
/// starts, `cw env logs --follow` and dashboard setup views together.
pub const MAX_LIVE_FOLLOWS_PER_ACCOUNT: usize = 8;
/// Signals buffered for the slowest follower. A follower that falls further
/// behind re-reads its environment instead.
const SIGNAL_CAPACITY: usize = 1024;
const LISTENER_RETRY: Duration = Duration::from_secs(1);
/// Environment ids are canonical UUIDs; anything longer is not one.
const MAX_PAYLOAD_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LogSignal {
    /// A row for this environment was committed.
    Environment(Arc<str>),
    /// Notifications may have been missed while the listener was not
    /// listening: every follower re-reads.
    Resync,
}

pub struct EnvironmentLogNotifications {
    signals: broadcast::Sender<LogSignal>,
    follows: Mutex<HashMap<String, usize>>,
    follows_per_account: usize,
}

impl EnvironmentLogNotifications {
    pub fn new(follows_per_account: usize) -> Arc<Self> {
        Self::with_capacity(follows_per_account, SIGNAL_CAPACITY)
    }

    pub(crate) fn with_capacity(follows_per_account: usize, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            signals: broadcast::channel(capacity).0,
            follows: Mutex::default(),
            follows_per_account,
        })
    }

    pub(crate) fn notify(&self, environment_id: &str) {
        if !environment_id.is_empty() && environment_id.len() <= MAX_PAYLOAD_BYTES {
            // No receiver simply means nobody is following.
            let _ = self
                .signals
                .send(LogSignal::Environment(environment_id.into()));
        }
    }

    pub(crate) fn resync(&self) {
        let _ = self.signals.send(LogSignal::Resync);
    }

    /// One live follow for `account_id`, or `None` at the account's limit.
    pub(crate) fn acquire_follow(self: &Arc<Self>, account_id: &str) -> Option<FollowPermit> {
        let mut follows = self
            .follows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let held = follows.get(account_id).copied().unwrap_or(0);
        if held >= self.follows_per_account {
            return None;
        }
        follows.insert(account_id.to_owned(), held + 1);
        Some(FollowPermit {
            notifications: self.clone(),
            account_id: account_id.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn follows(&self, account_id: &str) -> usize {
        self.follows
            .lock()
            .unwrap()
            .get(account_id)
            .copied()
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn subscribers(&self) -> usize {
        self.signals.receiver_count()
    }
}

/// A held live follow. It subscribes its follower and releases the account's
/// slot when dropped, which is when the follow ends for any reason.
pub(crate) struct FollowPermit {
    notifications: Arc<EnvironmentLogNotifications>,
    account_id: String,
}

impl FollowPermit {
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<LogSignal> {
        self.notifications.signals.subscribe()
    }
}

impl Drop for FollowPermit {
    fn drop(&mut self) {
        let mut follows = self
            .notifications
            .follows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match follows.get_mut(&self.account_id) {
            Some(held) if *held > 1 => *held -= 1,
            _ => {
                follows.remove(&self.account_id);
            }
        }
    }
}

/// Runs the process-wide `LISTEN environment_logs` loop on `pool`,
/// reconnecting after failures. Every successful (re)subscription is
/// followed by a resync, since rows committed meanwhile sent no signal.
pub fn spawn_environment_log_listener(
    pool: PgPool,
    notifications: Arc<EnvironmentLogNotifications>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = listen(&pool, &notifications).await {
                tracing::warn!(error = %error, "environment log notification listener failed");
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    })
}

async fn listen(pool: &PgPool, notifications: &EnvironmentLogNotifications) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(ENVIRONMENT_LOGS_CHANNEL).await?;
    notifications.resync();
    loop {
        // `None` is a lost connection. Reconnect here rather than inside
        // sqlx, so the resync above always follows the new subscription.
        let Some(notification) = listener.try_recv().await? else {
            anyhow::bail!("environment log listener connection lost");
        };
        notifications.notify(notification.payload());
    }
}
