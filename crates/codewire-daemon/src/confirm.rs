//! Confirm-waits for cleanup: a bounded number of checks of an event.
use std::future::Future;
use std::time::Duration;

/// How long a confirm-wait sleeps between two checks of its event.
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_millis(10);

/// The number of checks a budget allows: the budget divided by
/// [`CHECK_INTERVAL`], so unstalled the wait lasts the nominal budget.
fn checks(budget: Duration) -> u128 {
    (budget.as_millis() / CHECK_INTERVAL.as_millis()).max(1)
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
    mut event: impl FnMut() -> Option<T>,
) -> Option<T> {
    let mut remaining = checks(budget);
    loop {
        if let Some(outcome) = event() {
            return Some(outcome);
        }
        remaining -= 1;
        if remaining == 0 {
            return None;
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

/// Awaits `future` for at most `budget / CHECK_INTERVAL` checks of
/// [`CHECK_INTERVAL`] each, counted as [`check_within`] counts them: a stall
/// uses up one check, and a future that never completes is refused after the
/// same number of checks. The future is not cancelled; the caller keeps it.
pub(crate) async fn await_within<F: Future + Unpin>(
    budget: Duration,
    future: &mut F,
) -> Option<F::Output> {
    let mut remaining = checks(budget);
    loop {
        if let Ok(output) = tokio::time::timeout(CHECK_INTERVAL, &mut *future).await {
            return Some(output);
        }
        remaining -= 1;
        if remaining == 0 {
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

    #[tokio::test]
    async fn a_future_is_awaited_for_the_budgets_checks_and_kept() {
        let (sender, receiver) = tokio::sync::oneshot::channel::<u8>();
        let mut receiver = receiver;
        assert!(
            await_within(Duration::from_millis(50), &mut receiver)
                .await
                .is_none()
        );
        sender.send(9).unwrap();
        assert_eq!(
            await_within(Duration::from_millis(50), &mut receiver).await,
            Some(Ok(9))
        );
    }
}
