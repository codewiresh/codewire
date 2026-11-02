//! A session launched with `end_after_detached_seconds` ends once no client
//! has been attached to it for that long (#3827). It is what makes the default
//! `cw shell` a shell that survives a brief drop yet is not left running once
//! its client has gone. A session without the setting never ends this way.
//!
//! - **Who counts.** Every client attachment is a daemon `AttachSession`
//!   stream, whether it came through the API or the workspace SSH server's
//!   session subsystem, and `service::run_attach_session` serves each one
//!   holding an [`Attached`] for as long as it runs.
//! - **The timer** runs while nobody is attached: from launch or restart until
//!   the first attachment, and from each last detach. An attachment cancels
//!   it; the next last detach starts a whole new grace.
//! - **Expiry** stops the session as an explicit stop does, under its
//!   operation lock: a PTY's process is hung up. The record says
//!   "ended: no client for N minutes".
//! - **Races.** Expiry first takes the session's operation lock, so it is
//!   serial with launch, stop and restart. It then decides under the presence
//!   lock, which every attachment takes to count itself: it ends the session
//!   only if nobody is attached and its timer is still the armed one. An
//!   attachment counted before that decision keeps the session running; one
//!   counted after it joins a session that is already ending and sees it end,
//!   with the reason. A restart arms a new timer, which retires the old one; a
//!   stop or an exit leaves nothing live to end. Daemon shutdown cancels every
//!   timer.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::{SessionEngine, SessionEngineInner, SessionHandle, is_live_state, lock};

/// A session's attached clients and its armed timer.
#[derive(Default)]
pub(super) struct Presence {
    attachments: usize,
    /// The armed timer: its number, and its cancellation.
    timer: Option<(u64, CancellationToken)>,
    /// The number of the last timer armed.
    armed: u64,
}

/// One attachment, counted on its session until it is dropped.
pub(crate) struct Attached {
    inner: Weak<SessionEngineInner>,
    session_id: String,
    handle: Arc<SessionHandle>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        let last = {
            let mut presence = lock(&self.handle.presence);
            presence.attachments = presence.attachments.saturating_sub(1);
            presence.attachments == 0
        };
        if last {
            arm(&self.inner, &self.session_id, &self.handle);
        }
    }
}

impl SessionEngine {
    /// Counts an attachment to `session_id` until the result is dropped, and
    /// cancels the session's timer. An unknown session counts nothing; its
    /// attachment fails on its first read.
    pub(crate) fn attached(&self, session_id: &str) -> Option<Attached> {
        let handle = self.handle(session_id).ok()?;
        {
            let mut presence = lock(&handle.presence);
            presence.attachments += 1;
            if let Some((_, timer)) = presence.timer.take() {
                timer.cancel();
            }
        }
        Some(Attached {
            inner: Arc::downgrade(&self.inner),
            session_id: session_id.to_owned(),
            handle,
        })
    }

    /// Starts the whole grace of a session launched with the setting, unless
    /// a client is attached. It replaces a timer already running.
    pub(super) fn arm_unattended(&self, session_id: &str, handle: &Arc<SessionHandle>) {
        arm(&Arc::downgrade(&self.inner), session_id, handle);
    }

    /// The timer `timer` ran out: ends the session if it is still the armed
    /// timer, nobody is attached and the session is live.
    async fn end_unattended(
        &self,
        session_id: &str,
        handle: &SessionHandle,
        timer: u64,
        grace: Duration,
    ) {
        let shutdown = self.inner.shutdown.clone();
        let _operation = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            operation = handle.operation.lock() => operation,
        };
        {
            let mut presence = lock(&handle.presence);
            let armed = presence.timer.as_ref().map(|(number, _)| *number);
            if presence.attachments != 0 || armed != Some(timer) {
                return;
            }
            presence.timer = None;
        }
        if !is_live_state(handle.metadata.lock().await.state) {
            return;
        }
        let reason = format!("ended: no client for {}", describe(grace));
        tracing::info!(
            session_id,
            reason,
            "ending a session with no client attached"
        );
        if let Err(error) = self
            .stop_active_because(session_id, handle, Some(reason))
            .await
        {
            tracing::warn!(
                session_id,
                %error,
                "could not end a session with no client attached"
            );
        }
    }
}

fn arm(inner: &Weak<SessionEngineInner>, session_id: &str, handle: &Arc<SessionHandle>) {
    let Some(grace) = handle.end_after_detached else {
        return;
    };
    let Some(shutdown) = inner.upgrade().map(|inner| inner.shutdown.clone()) else {
        return;
    };
    // The last attachment can be dropped while the runtime itself is going
    // down; nothing is left to end then.
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if shutdown.is_cancelled() {
        return;
    }
    let cancel = CancellationToken::new();
    let timer = {
        let mut presence = lock(&handle.presence);
        if presence.attachments != 0 {
            return;
        }
        if let Some((_, previous)) = presence.timer.take() {
            previous.cancel();
        }
        presence.armed += 1;
        presence.timer = Some((presence.armed, cancel.clone()));
        presence.armed
    };
    let (inner, session_id, handle) = (inner.clone(), session_id.to_owned(), handle.clone());
    runtime.spawn(async move {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(grace) => {}
        }
        let Some(inner) = inner.upgrade() else {
            return;
        };
        SessionEngine { inner }
            .end_unattended(&session_id, &handle, timer, grace)
            .await;
    });
}

/// Test seams: the armed timer, an expiry run at once, and the operation lock
/// held as a stop or restart in progress holds it.
#[cfg(test)]
impl SessionEngine {
    pub(crate) fn unattended_timer(&self, session_id: &str) -> Option<u64> {
        let handle = self.handle(session_id).ok()?;
        lock(&handle.presence)
            .timer
            .as_ref()
            .map(|(number, _)| *number)
    }

    pub(crate) async fn expire_unattended(&self, session_id: &str, timer: u64) {
        let handle = self.handle(session_id).expect("a known session");
        let grace = handle
            .end_after_detached
            .expect("a session launched with the setting");
        self.end_unattended(session_id, &handle, timer, grace).await;
    }

    pub(crate) async fn hold_test_operation_lock(
        &self,
        session_id: &str,
        held: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        let handle = self.handle(session_id).expect("a known session");
        let _operation = handle.operation.lock().await;
        let _ = held.send(());
        let _ = release.await;
    }
}

/// The grace in the largest whole unit: "10 minutes", "1 hour", "90 seconds".
fn describe(grace: Duration) -> String {
    let seconds = grace.as_secs();
    let (count, unit) = [(86_400, "day"), (3_600, "hour"), (60, "minute")]
        .into_iter()
        .find(|(size, _)| seconds.is_multiple_of(*size))
        .map_or((seconds, "second"), |(size, unit)| (seconds / size, unit));
    format!("{count} {unit}{}", if count == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reason_names_the_grace_in_its_largest_whole_unit() {
        for (seconds, expected) in [
            (1, "1 second"),
            (90, "90 seconds"),
            (60, "1 minute"),
            (600, "10 minutes"),
            (3_600, "1 hour"),
            (5_400, "90 minutes"),
            (604_800, "7 days"),
        ] {
            assert_eq!(describe(Duration::from_secs(seconds)), expected);
        }
    }
}
