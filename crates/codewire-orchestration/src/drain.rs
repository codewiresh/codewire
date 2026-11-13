//! This replica's drain when a rollout replaces it (#4426).
//!
//! SIGTERM, which a rollout sends only after the preStop delay has taken the
//! replica out of the gateway, begins the drain: leadership and Temporal tasks
//! go at once, and streams whose clients re-attach end. The deadline,
//! [`DRAIN_WINDOW`] later and before the termination grace runs out, ends
//! every stream still open with a retryable error, where the kill would
//! leave its client a protocol reset.

use std::time::Duration;

use codewire_daemon_bridge::drain::{Restart, RestartSignal};
use tokio_util::sync::CancellationToken;

/// SIGTERM to the deadline. The Deployment's 300 s grace starts with its
/// 10 s preStop sleep; a 20 s margin before SIGKILL leaves 270 s.
pub const DRAIN_WINDOW: Duration = Duration::from_secs(270);

#[derive(Clone, Default)]
pub struct Drain {
    begun: CancellationToken,
    deadline: CancellationToken,
}

impl Drain {
    /// Begins the drain now; its deadline comes `window` later.
    pub fn begin(&self, window: Duration) {
        self.begun.cancel();
        let deadline = self.deadline.clone();
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            deadline.cancel();
        });
    }

    /// Cancelled once the drain has begun.
    pub fn begun(&self) -> CancellationToken {
        self.begun.clone()
    }

    /// Completes once the drain reaches `restart`.
    pub fn signal(&self, restart: Restart) -> RestartSignal {
        let token = match restart {
            Restart::Begins => self.begun.clone(),
            Restart::Deadline => self.deadline.clone(),
        };
        Box::pin(token.cancelled_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_deadline_follows_the_beginning_by_the_window() {
        let drain = Drain::default();
        let mut begins = drain.signal(Restart::Begins);
        let mut deadline = drain.signal(Restart::Deadline);
        assert!(futures::poll!(begins.as_mut()).is_pending());

        drain.begin(Duration::from_secs(270));
        assert!(futures::poll!(begins.as_mut()).is_ready());
        assert!(drain.begun().is_cancelled());
        tokio::time::sleep(Duration::from_secs(269)).await;
        assert!(futures::poll!(deadline.as_mut()).is_pending());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(futures::poll!(deadline.as_mut()).is_ready());
    }
}
