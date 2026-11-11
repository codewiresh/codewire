//! Confirm-waits for cleanup: a bounded number of checks of an event.
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How long a confirm-wait sleeps between two checks of its event.
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_millis(10);

/// The number of checks a budget allows: the budget divided by
/// [`CHECK_INTERVAL`], so unstalled the wait lasts the nominal budget.
fn checks(budget: Duration) -> u128 {
    (budget.as_millis() / CHECK_INTERVAL.as_millis()).max(1)
}

/// A pool of confirm checks that every step of one cleanup spends from, so
/// the cleanup as a whole, not each of its steps, is bounded (#3777). Steps
/// that wait at the same time draw on it together. A step that starts after
/// the pool ran out still checks its event once, so an outcome that is
/// already there is confirmed.
#[derive(Debug)]
pub(crate) struct CheckBudget {
    remaining: AtomicU64,
}

impl CheckBudget {
    pub(crate) fn new(budget: Duration) -> Self {
        Self {
            remaining: AtomicU64::new(u64::try_from(checks(budget)).unwrap_or(u64::MAX)),
        }
    }

    /// Spends one check after an event was not there; false once none is
    /// left, as the last check of a fresh budget is.
    fn spend(&self) -> bool {
        let previous = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .unwrap_or(0);
        previous > 1
    }
}

/// Checks `event` until it reports an outcome, at most `budget /
/// CHECK_INTERVAL` times, sleeping [`CHECK_INTERVAL`] between checks.
///
/// The budget counts checks, not wall-clock time. A stall of the whole
/// process (a suspended laptop, a paused VM, a CI slot that freezes for
/// seconds) delays one sleep, so it uses up one check instead of the whole
/// budget, and a cleanup that completed during the stall is still confirmed.
/// An event that never comes, such as a child that does not die, is refused
/// after the same number of checks, which takes at least the nominal budget:
/// the wait still fails closed and is never longer per check.
pub(crate) async fn check_within<T>(
    budget: Duration,
    event: impl FnMut() -> Option<T>,
) -> Option<T> {
    check_spending(&CheckBudget::new(budget), event).await
}

/// [`check_within`], spending its checks from a shared [`CheckBudget`].
pub(crate) async fn check_spending<T>(
    budget: &CheckBudget,
    mut event: impl FnMut() -> Option<T>,
) -> Option<T> {
    loop {
        if let Some(outcome) = event() {
            return Some(outcome);
        }
        if !budget.spend() {
            return None;
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

/// Awaits `future` for at most the budget's remaining checks of
/// [`CHECK_INTERVAL`] each, counted as [`check_within`] counts them: a stall
/// uses up one check, and a future that never completes is refused once the
/// checks run out. The future is not cancelled; the caller keeps it.
pub(crate) async fn await_spending<F: Future + Unpin>(
    budget: &CheckBudget,
    future: &mut F,
) -> Option<F::Output> {
    loop {
        if let Ok(output) = tokio::time::timeout(CHECK_INTERVAL, &mut *future).await {
            return Some(output);
        }
        if !budget.spend() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn an_event_that_never_comes_is_refused_after_the_budgets_checks() {
        let calls = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let started = std::time::Instant::now();
        let outcome = check_within::<()>(Duration::from_millis(200), move || {
            counted.fetch_add(1, Ordering::SeqCst);
            None
        })
        .await;
        assert!(outcome.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 20);
        // Never shorter than the nominal budget, less the one unslept check.
        assert!(started.elapsed() >= Duration::from_millis(190));
    }

    #[tokio::test]
    async fn a_stall_longer_than_the_budget_uses_one_check() {
        // The first check stalls past the whole budget, as a frozen process
        // does; the event is there at the next check. A wall-clock deadline
        // would refuse it here, after one check.
        let calls = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let outcome = check_within(Duration::from_millis(200), move || {
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(400));
                return None;
            }
            Some(())
        })
        .await;
        assert_eq!(outcome, Some(()));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_event_is_returned_at_the_check_that_sees_it() {
        let calls = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let outcome = check_within(Duration::from_secs(1), move || {
            (counted.fetch_add(1, Ordering::SeqCst) == 3).then_some(7)
        })
        .await;
        assert_eq!(outcome, Some(7));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    /// Steps of one cleanup spend one pool (#3777): what the first step
    /// used is gone for the next, and a step that starts with nothing left
    /// still checks its event once.
    #[tokio::test]
    async fn a_shared_budget_is_spent_across_steps() {
        let budget = CheckBudget::new(Duration::from_millis(200));
        let calls = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let first = check_spending(&budget, move || {
            (counted.fetch_add(1, Ordering::SeqCst) == 14).then_some(())
        })
        .await;
        assert_eq!(first, Some(()));
        assert_eq!(calls.load(Ordering::SeqCst), 15);

        let calls = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&calls);
        let second = check_spending::<()>(&budget, move || {
            counted.fetch_add(1, Ordering::SeqCst);
            None
        })
        .await;
        assert!(second.is_none());
        // 20 checks in all: 15 spent above, the rest here.
        assert_eq!(calls.load(Ordering::SeqCst), 6);

        let already_there = check_spending(&budget, || Some(3)).await;
        assert_eq!(already_there, Some(3));
    }

    #[tokio::test]
    async fn a_future_is_awaited_for_the_budgets_checks_and_kept() {
        let (sender, receiver) = tokio::sync::oneshot::channel::<u8>();
        let mut receiver = receiver;
        assert!(
            await_spending(&CheckBudget::new(Duration::from_millis(50)), &mut receiver)
                .await
                .is_none()
        );
        sender.send(9).unwrap();
        assert_eq!(
            await_spending(&CheckBudget::new(Duration::from_millis(50)), &mut receiver).await,
            Some(Ok(9))
        );
    }
}
