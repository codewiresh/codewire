//! Whether this replica leads, and the leader-gated passes it is running.
//!
//! A loop runs each pass under a [`LeaderPass`], which it gets only while
//! this replica leads. Stepping down when the replica drains (#4426) stops new
//! passes and waits for the running ones, so the next leader never runs a
//! pass beside one of this replica's.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct Leadership {
    state: Mutex<State>,
    idle: Notify,
}

#[derive(Default)]
struct State {
    leading: bool,
    passes: usize,
}

impl Leadership {
    /// Whether this replica leads now, for tests; a pass takes
    /// [`Self::pass`] instead.
    #[cfg(test)]
    pub(crate) fn leads(&self) -> bool {
        self.state().leading
    }

    /// A pass while this replica leads; `None` once it does not. Checked and
    /// counted together, so no pass starts after [`Self::step_down`] decides.
    pub(crate) fn pass(self: &Arc<Self>) -> Option<LeaderPass> {
        let mut state = self.state();
        if !state.leading {
            return None;
        }
        state.passes += 1;
        Some(LeaderPass(self.clone()))
    }

    pub(super) fn acquired(&self) {
        self.state().leading = true;
    }

    /// Leadership went with the lock's connection. Nothing waits: another
    /// replica may already hold the lock, as it always could on a lost
    /// connection, and running passes end at their next leadership check.
    pub(super) fn lost(&self) {
        self.state().leading = false;
    }

    /// Stops new passes and waits at most `bound` for the running ones to
    /// end, before the caller releases the lock. False when some still run.
    pub(super) async fn step_down(&self, bound: Duration) -> bool {
        self.state().leading = false;
        tokio::time::timeout(bound, async {
            loop {
                let idle = self.idle.notified();
                tokio::pin!(idle);
                // Registered before the check, so the last pass's wake-up
                // cannot fall between the check and the wait.
                idle.as_mut().enable();
                if self.state().passes == 0 {
                    return;
                }
                idle.await;
            }
        })
        .await
        .is_ok()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // The count stays right after a panic elsewhere: every change is a
        // single assignment under the lock.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One running leader-gated pass; dropping it ends the pass.
pub(crate) struct LeaderPass(Arc<Leadership>);

impl Drop for LeaderPass {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.passes -= 1;
        if state.passes == 0 {
            self.0.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_needs_leadership() {
        let leadership = Arc::new(Leadership::default());
        assert!(leadership.pass().is_none());
        leadership.acquired();
        assert!(leadership.pass().is_some());
        leadership.lost();
        assert!(leadership.pass().is_none());
    }

    #[tokio::test]
    async fn stepping_down_waits_for_the_running_pass_and_starts_no_new_one() {
        let leadership = Arc::new(Leadership::default());
        leadership.acquired();
        let running = leadership.pass().expect("a leader starts a pass");
        let step_down = tokio::spawn({
            let leadership = leadership.clone();
            async move { leadership.step_down(Duration::from_secs(5)).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !step_down.is_finished(),
            "stepped down under a running pass"
        );
        assert!(!leadership.leads());
        assert!(
            leadership.pass().is_none(),
            "a pass started after the decision"
        );
        drop(running);
        assert!(step_down.await.expect("step down task"));
    }

    #[tokio::test(start_paused = true)]
    async fn stepping_down_gives_up_waiting_at_its_bound() {
        let leadership = Arc::new(Leadership::default());
        leadership.acquired();
        let _stuck = leadership.pass().expect("a leader starts a pass");
        assert!(!leadership.step_down(Duration::from_secs(60)).await);
    }
}
