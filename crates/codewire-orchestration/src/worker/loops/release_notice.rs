//! The draining leader's notice that the lock is free (#6099). A standby
//! waits on it instead of polling, so it leads as soon as the lock is
//! released, not up to a retry later. The retry stays as the fallback for a
//! leader that ends without sending one.

use std::time::Duration;

use sqlx::PgConnection;
use sqlx::postgres::PgListener;
use tokio_util::sync::CancellationToken;

use super::{ADVISORY_LOCK_ID, drained_during};

const CHANNEL: &str = "codewire_orchestration_leader_released";

/// Subscribes a standby to the notice. A standby subscribes before it tries
/// the lock, so a release between a failed try and the wait still wakes it.
/// `None` when listening failed; the standby then polls.
pub(super) async fn subscribe(database_url: &str) -> Option<PgListener> {
    let subscribed = async {
        let mut listener = PgListener::connect(database_url).await?;
        listener.listen(CHANNEL).await?;
        Ok::<_, sqlx::Error>(listener)
    };
    match subscribed.await {
        Ok(listener) => Some(listener),
        Err(error) => {
            tracing::warn!(%error, "leader: listening for the release notice failed; polling");
            None
        }
    }
}

/// Waits up to `retry` for the notice, or until draining starts; true when
/// it has. A listener that fails is dropped, so the next try subscribes
/// again, and the rest of `retry` is slept so a broken listener never spins.
pub(super) async fn wait(
    notice: &mut Option<PgListener>,
    draining: &CancellationToken,
    retry: Duration,
) -> bool {
    let Some(listener) = notice.as_mut() else {
        return drained_during(draining, retry).await;
    };
    let deadline = tokio::time::Instant::now() + retry;
    let received = tokio::select! {
        () = draining.cancelled() => return true,
        received = tokio::time::timeout_at(deadline, listener.recv()) => received,
    };
    if let Ok(Err(error)) = received {
        tracing::warn!(%error, "leader: the release notice's listener failed; polling");
        *notice = None;
        let rest = deadline.saturating_duration_since(tokio::time::Instant::now());
        return drained_during(draining, rest).await;
    }
    false
}

/// Releases the lock on the leader's own session, then tells every standby.
/// The notice follows the unlock, so a standby it wakes finds the lock free.
pub(super) async fn release(conn: &mut PgConnection) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT pg_notify($1, '')")
        .bind(CHANNEL)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
