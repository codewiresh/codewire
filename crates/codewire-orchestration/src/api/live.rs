//! Live change notices for signed-in pages (#4762; private-docs
//! designs/live-updates.md).
//!
//! One process-wide `LISTEN` on `environment_changes`, `resize_changes` and
//! `credit_changes` fans each notice out over a broadcast channel, as
//! [`super::log_notifications`] does for environment logs. Each watch keeps
//! the notices for the organizations its caller belonged to when it opened,
//! and passes on only identifiers: the page re-fetches what it shows, and
//! that read is authorized as usual. A watch never relies on a single notice:
//! it starts with a resync, and sends another after a listener reconnect or
//! when it fell behind the channel.
//!
//! The organizations are read once per watch, so a member removed meanwhile
//! keeps receiving that organization's identifiers until the watch ends, at
//! most [`WATCH_LIFETIME`] later. That is safe only because every re-fetch
//! they lead to re-authorizes; a new watch no longer includes it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::mpsc::{self, error::TrySendError};

pub(crate) const ENVIRONMENT_CHANGES_CHANNEL: &str = "environment_changes";
pub(crate) const RESIZE_CHANGES_CHANNEL: &str = "resize_changes";
pub(crate) const CREDIT_CHANGES_CHANNEL: &str = "credit_changes";
/// Watches one account may hold at once in this process: about one per open
/// signed-in tab.
pub const MAX_WATCHES_PER_ACCOUNT: usize = 16;
/// How long one watch lasts before its caller opens a new one, which bounds
/// how long a removed member's cached organizations stay in use.
pub(crate) const WATCH_LIFETIME: Duration = Duration::from_secs(10 * 60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Events queued for one watch's reader. A reader this far behind gets one
/// resync when it catches up instead of every change it missed.
const QUEUE_CAPACITY: usize = 256;
/// Notices buffered for the slowest watch; one further behind resyncs.
const SIGNAL_CAPACITY: usize = 4096;
const LISTENER_RETRY: Duration = Duration::from_secs(1);
/// Organization and environment ids are short; anything longer is not one.
const MAX_ID_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveSignal {
    Sandbox {
        org: Arc<str>,
        environment: Arc<str>,
    },
    Resize {
        org: Arc<str>,
        environment: Arc<str>,
    },
    Credit {
        org: Arc<str>,
    },
    /// Notices may have been missed while the listener was not listening.
    Resync,
}

impl LiveSignal {
    fn org(&self) -> Option<&str> {
        match self {
            Self::Sandbox { org, .. } | Self::Resize { org, .. } | Self::Credit { org } => {
                Some(org)
            }
            Self::Resync => None,
        }
    }

    /// The signal a notice on `channel` carries, or `None` for a payload that
    /// is not one this migration's triggers send.
    pub(crate) fn from_notice(channel: &str, payload: &str) -> Option<Self> {
        match channel {
            CREDIT_CHANGES_CHANNEL => valid_id(payload).then(|| Self::Credit {
                org: payload.into(),
            }),
            ENVIRONMENT_CHANGES_CHANNEL | RESIZE_CHANGES_CHANNEL => {
                let (org, environment) = payload.split_once(':')?;
                if !valid_id(org) || !valid_id(environment) {
                    return None;
                }
                let (org, environment) = (org.into(), environment.into());
                Some(if channel == RESIZE_CHANGES_CHANNEL {
                    Self::Resize { org, environment }
                } else {
                    Self::Sandbox { org, environment }
                })
            }
            _ => None,
        }
    }
}

fn valid_id(value: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// What a watch sends its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveEvent {
    Resync,
    Heartbeat(DateTime<Utc>),
    Sandbox {
        org: Arc<str>,
        environment: Arc<str>,
    },
    Resize {
        org: Arc<str>,
        environment: Arc<str>,
    },
    Credit {
        org: Arc<str>,
    },
}

pub struct LiveNotifications {
    signals: broadcast::Sender<LiveSignal>,
    watches: Mutex<HashMap<String, usize>>,
    watches_per_account: usize,
}

impl LiveNotifications {
    pub fn new(watches_per_account: usize) -> Arc<Self> {
        Self::with_capacity(watches_per_account, SIGNAL_CAPACITY)
    }

    pub(crate) fn with_capacity(watches_per_account: usize, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            signals: broadcast::channel(capacity).0,
            watches: Mutex::default(),
            watches_per_account,
        })
    }

    pub(crate) fn notify(&self, channel: &str, payload: &str) {
        if let Some(signal) = LiveSignal::from_notice(channel, payload) {
            // No receiver simply means nobody is watching.
            let _ = self.signals.send(signal);
        }
    }

    pub(crate) fn resync(&self) {
        let _ = self.signals.send(LiveSignal::Resync);
    }

    /// One watch for `account_id`, or `None` at the account's limit.
    pub(crate) fn acquire_watch(self: &Arc<Self>, account_id: &str) -> Option<WatchPermit> {
        let mut watches = self
            .watches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let held = watches.get(account_id).copied().unwrap_or(0);
        if held >= self.watches_per_account {
            return None;
        }
        watches.insert(account_id.to_owned(), held + 1);
        Some(WatchPermit {
            notifications: self.clone(),
            account_id: account_id.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn watches(&self, account_id: &str) -> usize {
        self.watches
            .lock()
            .unwrap()
            .get(account_id)
            .copied()
            .unwrap_or(0)
    }
}

/// A held watch. It releases the account's slot when dropped, which is when
/// the watch ends for any reason.
pub(crate) struct WatchPermit {
    notifications: Arc<LiveNotifications>,
    account_id: String,
}

impl WatchPermit {
    fn subscribe(&self) -> broadcast::Receiver<LiveSignal> {
        self.notifications.signals.subscribe()
    }
}

impl Drop for WatchPermit {
    fn drop(&mut self) {
        let mut watches = self
            .notifications
            .watches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match watches.get_mut(&self.account_id) {
            Some(held) if *held > 1 => *held -= 1,
            _ => {
                watches.remove(&self.account_id);
            }
        }
    }
}

/// The process's live notifications, with their listener running on `pool`.
pub fn start(pool: PgPool) -> Arc<LiveNotifications> {
    let notifications = LiveNotifications::new(MAX_WATCHES_PER_ACCOUNT);
    spawn_live_listener(pool, notifications.clone());
    notifications
}

/// Runs the process-wide listener on `pool`, reconnecting after failures.
/// Every successful (re)subscription is followed by a resync, since changes
/// committed meanwhile sent no notice anyone heard.
pub fn spawn_live_listener(
    pool: PgPool,
    notifications: Arc<LiveNotifications>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = listen(&pool, &notifications).await {
                tracing::warn!(error = %error, "live change listener failed");
            }
            tokio::time::sleep(LISTENER_RETRY).await;
        }
    })
}

async fn listen(pool: &PgPool, notifications: &LiveNotifications) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener
        .listen_all([
            ENVIRONMENT_CHANGES_CHANNEL,
            RESIZE_CHANGES_CHANNEL,
            CREDIT_CHANGES_CHANNEL,
        ])
        .await?;
    notifications.resync();
    loop {
        // `None` is a lost connection. Reconnect here rather than inside
        // sqlx, so the resync above always follows the new subscription.
        let Some(notice) = listener.try_recv().await? else {
            anyhow::bail!("live change listener connection lost");
        };
        notifications.notify(notice.channel(), notice.payload());
    }
}

/// Opens a watch for `user`: its organizations now, within the account's
/// limit. An API key sees only its own organization.
pub(crate) async fn open_live_watch(
    pool: &PgPool,
    notifications: &Arc<LiveNotifications>,
    user: &AuthUser,
) -> AppResult<mpsc::Receiver<LiveEvent>> {
    let permit = notifications
        .acquire_watch(&user.user_id)
        .ok_or_else(watch_limit_exceeded)?;
    let organizations: Vec<String> =
        sqlx::query_scalar("SELECT org_id FROM org_members WHERE user_id = $1")
            .bind(&user.user_id)
            .fetch_all(pool)
            .await?;
    let organizations = organizations
        .into_iter()
        .filter(|org| user.permits_organization(org))
        .collect();
    Ok(start_live_watch(
        organizations,
        permit,
        WATCH_LIFETIME,
        HEARTBEAT_INTERVAL,
        QUEUE_CAPACITY,
    ))
}

fn watch_limit_exceeded() -> AppError {
    AppError::Coded {
        status: StatusCode::TOO_MANY_REQUESTS,
        code: "live_watch_limit_exceeded",
        detail: "too many live views are open for this account; close one and try again".into(),
    }
}

/// Starts a watch over `organizations`. It sends a resync first, a heartbeat
/// every `heartbeat`, the identifiers of each matching change, and another
/// resync after any gap; it ends after `lifetime` or when its reader goes.
/// At most `capacity` events wait for the reader: when the queue is full the
/// watch drops events and owes one resync, sent as soon as there is room, so a
/// reader that stops reading costs a bounded queue, not a growing one.
pub(crate) fn start_live_watch(
    organizations: HashSet<String>,
    permit: WatchPermit,
    lifetime: Duration,
    heartbeat: Duration,
    capacity: usize,
) -> mpsc::Receiver<LiveEvent> {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    tokio::spawn(async move {
        // Subscribe before the first resync, so a change committed while the
        // page re-fetches still arrives.
        let mut signals = permit.subscribe();
        if tx.try_send(LiveEvent::Resync).is_err() {
            return;
        }
        let ends = tokio::time::sleep(lifetime);
        tokio::pin!(ends);
        let mut beat = tokio::time::interval(heartbeat);
        beat.tick().await; // the first tick is immediate; skip it
        let mut owes_resync = false;
        loop {
            let event = tokio::select! {
                () = tx.closed() => return,
                () = &mut ends => return,
                _ = beat.tick() => LiveEvent::Heartbeat(Utc::now()),
                signal = signals.recv() => match signal {
                    Ok(signal) => {
                        if !signal.org().is_none_or(|org| organizations.contains(org)) {
                            continue;
                        }
                        match signal {
                            LiveSignal::Sandbox { org, environment } => LiveEvent::Sandbox { org, environment },
                            LiveSignal::Resize { org, environment } => LiveEvent::Resize { org, environment },
                            LiveSignal::Credit { org } => LiveEvent::Credit { org },
                            LiveSignal::Resync => LiveEvent::Resync,
                        }
                    }
                    Err(RecvError::Lagged(_)) => LiveEvent::Resync,
                    Err(RecvError::Closed) => return,
                },
            };
            if owes_resync {
                match tx.try_send(LiveEvent::Resync) {
                    Ok(()) => owes_resync = false,
                    Err(TrySendError::Full(_)) => continue,
                    Err(TrySendError::Closed(_)) => return,
                }
                if event == LiveEvent::Resync {
                    continue;
                }
            }
            match tx.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => owes_resync = true,
                Err(TrySendError::Closed(_)) => return,
            }
        }
    });
    rx
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
