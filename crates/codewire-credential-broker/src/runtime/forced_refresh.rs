//! When a provider's 401 may force a refresh of a stored sign-in (#3999).

use std::time::Duration;

/// How long ago a sign-in must last have been refreshed before a provider
/// 401 may force another refresh of it.
///
/// A process in the environment shapes the request and so decides when a 401
/// happens. Every forced exchange rotates the refresh token, and one the
/// provider refuses, or whose outcome is uncertain (a 429, a 5xx, a timeout,
/// a network error), leaves the sign-in "Reconnect needed", as every refresh
/// does. This age is what bounds how often such a process can cause one.
///
/// The time compared is the one stored in the sign-in itself, which every
/// exchange rewrites. So the bound holds for one sign-in across every broker
/// that serves it and across their restarts, which a count kept in one
/// broker's memory would not. It also means a token that was refreshed
/// moments ago and is still rejected is not refreshed again: another
/// exchange would not fix that 401.
pub(super) const FORCED_REFRESH_MIN_AGE: Duration = Duration::from_secs(10 * 60);

/// Whether a 401 may force a refresh of a sign-in last refreshed at
/// `refreshed_at_unix`. One stamped in the future is not due.
pub(super) fn forced_refresh_due(refreshed_at_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(refreshed_at_unix) >= FORCED_REFRESH_MIN_AGE.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const MIN_AGE: u64 = 600;

    #[test]
    fn the_age_is_ten_minutes() {
        assert_eq!(FORCED_REFRESH_MIN_AGE.as_secs(), MIN_AGE);
    }

    #[test]
    fn a_sign_in_younger_than_the_age_is_not_due() {
        assert!(!forced_refresh_due(NOW - (MIN_AGE - 1), NOW));
        assert!(!forced_refresh_due(NOW, NOW));
    }

    #[test]
    fn a_sign_in_of_exactly_the_age_is_due() {
        assert!(forced_refresh_due(NOW - MIN_AGE, NOW));
    }

    #[test]
    fn an_older_sign_in_is_due() {
        assert!(forced_refresh_due(NOW - MIN_AGE - 1, NOW));
        assert!(forced_refresh_due(0, NOW));
    }

    #[test]
    fn a_sign_in_stamped_in_the_future_is_not_due() {
        assert!(!forced_refresh_due(NOW + 1, NOW));
        assert!(!forced_refresh_due(u64::MAX, NOW));
    }
}
