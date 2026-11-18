//! When a serving broker child is replaced, and what its replacement must
//! resolve (#5286; `docs/dev/SECRETS-AND-CREDENTIALS.md`, "A provider that
//! can't be looked up when a local VM starts").

use std::collections::BTreeSet;
use std::time::Duration;

use tokio::time::Instant;

use crate::broker_process::ProviderLookup;

/// How long one broker child takes new work, from its spawn. A child resolves
/// provider addresses and opens its authority channel once, at its start, so
/// this bounds their age. It also ends no later than an owner-local platform
/// delegation, which the platform admits for at most 600 seconds.
const BROKER_EPOCH_LIFETIME: Duration = Duration::from_secs(600);
/// Its successor is spawned this long before that lifetime ends. Once the
/// successor runs, the daemon sends it all new work, and the predecessor only
/// finishes the requests already sent to it until its lifetime ends.
const BROKER_SUCCESSOR_LEAD: Duration = Duration::from_secs(90);
/// Between successor attempts while the predecessor still serves: 3 seconds,
/// doubling to at most 15.
const BROKER_SUCCESSOR_RETRY_FIRST: Duration = Duration::from_secs(3);
const BROKER_SUCCESSOR_RETRY_MAX: Duration = Duration::from_secs(15);
/// While a serving child has a provider it could not look up, an early
/// replacement tries to get it back: first after 5 seconds, then at intervals
/// that double to at most a minute, until the regular replacement is due.
const BROKER_RECOVERY_FIRST: Duration = Duration::from_secs(5);
const BROKER_RECOVERY_MAX: Duration = Duration::from_secs(60);

/// When a broker child is replaced: the constants above, shortened only by
/// tests.
#[derive(Clone, Copy, Debug)]
pub(super) struct BrokerRenewal {
    pub(super) lifetime: Duration,
    pub(super) lead: Duration,
    pub(super) recovery_first: Duration,
    pub(super) recovery_max: Duration,
}

impl BrokerRenewal {
    pub(super) const PRODUCTION: Self = Self {
        lifetime: BROKER_EPOCH_LIFETIME,
        lead: BROKER_SUCCESSOR_LEAD,
        recovery_first: BROKER_RECOVERY_FIRST,
        recovery_max: BROKER_RECOVERY_MAX,
    };

    /// When the regular replacement of a child whose lifetime ends at
    /// `ends_at` starts.
    fn regular(&self, ends_at: Instant, now: Instant) -> Instant {
        ends_at.checked_sub(self.lead).unwrap_or(now)
    }

    /// Whether a replacement started now, beside a serving child that left
    /// `unresolved` and ends at `ends_at`, is an early one for a provider's
    /// sake: the child has an unserved provider and its regular replacement
    /// is not due yet.
    fn recovering(&self, unresolved: &BTreeSet<String>, ends_at: Instant, now: Instant) -> bool {
        !unresolved.is_empty() && now < self.regular(ends_at, now)
    }

    /// When the next replacement of the serving child starts, after `failed`
    /// replacements of it could not start. An early replacement is never
    /// later than the regular one, which comes whatever the early ones did.
    pub(super) fn next_replacement(
        &self,
        unresolved: &BTreeSet<String>,
        ends_at: Instant,
        now: Instant,
        failed: u32,
    ) -> Instant {
        let regular = self.regular(ends_at, now);
        if self.recovering(unresolved, ends_at, now) {
            let delay = doubled(self.recovery_first, self.recovery_max, failed);
            return regular.min(now + delay);
        }
        match failed.checked_sub(1) {
            None => regular,
            Some(earlier) => {
                now + doubled(
                    BROKER_SUCCESSOR_RETRY_FIRST,
                    BROKER_SUCCESSOR_RETRY_MAX,
                    earlier,
                )
            }
        }
    }

    /// What a child started now is told about hosts that do not resolve.
    /// With none serving it starts whatever resolves. A regular replacement
    /// may leave unresolved only what the serving child does; an early one
    /// must also get at least one of those hosts back, or it would replace a
    /// working child for nothing.
    pub(super) fn lookup_beside(
        &self,
        serving: Option<(&BTreeSet<String>, Instant)>,
        now: Instant,
    ) -> ProviderLookup {
        match serving {
            None => ProviderLookup::Available,
            Some((unresolved, ends_at)) if self.recovering(unresolved, ends_at, now) => {
                ProviderLookup::FewerThan(unresolved.clone())
            }
            Some((unresolved, _)) => ProviderLookup::NoFewerThan(unresolved.clone()),
        }
    }
}

/// `first`, doubled `times` times, to at most `max`.
fn doubled(first: Duration, max: Duration, times: u32) -> Duration {
    first
        .checked_mul(2_u32.saturating_pow(times.min(8)))
        .map_or(max, |delay| delay.min(max))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RENEWAL: BrokerRenewal = BrokerRenewal::PRODUCTION;

    fn hosts(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// A child with every provider served is replaced once, 90 seconds
    /// before its 600-second lifetime ends, and a replacement that cannot
    /// start is retried after 3 seconds, doubling to 15.
    #[test]
    fn a_child_serving_every_provider_is_replaced_on_the_regular_schedule() {
        let now = Instant::now();
        let ends_at = now + Duration::from_secs(600);
        let none = hosts(&[]);
        let after = |failed| RENEWAL.next_replacement(&none, ends_at, now, failed) - now;
        assert_eq!(after(0), Duration::from_secs(510));
        assert_eq!(
            [1, 2, 3, 4, 9].map(after),
            [3, 6, 12, 15, 15].map(Duration::from_secs)
        );
        assert_eq!(
            RENEWAL.lookup_beside(Some((&none, ends_at)), now),
            ProviderLookup::NoFewerThan(none.clone())
        );
        assert_eq!(RENEWAL.lookup_beside(None, now), ProviderLookup::Available);
    }

    /// A child that left a provider unresolved gets early replacements:
    /// after 5 seconds, then doubling to a minute, each told to get a host
    /// back. None is later than the regular replacement, and from then on a
    /// replacement is a regular one again, which may leave what the child
    /// left.
    #[test]
    fn a_child_with_an_unserved_provider_gets_early_replacements_until_the_regular_one() {
        let began = Instant::now();
        let ends_at = began + Duration::from_secs(600);
        let left = hosts(&["api.anthropic.com"]);
        let after = |failed| RENEWAL.next_replacement(&left, ends_at, began, failed) - began;
        assert_eq!(
            [0, 1, 2, 3, 4, 5, 20].map(after),
            [5, 10, 20, 40, 60, 60, 60].map(Duration::from_secs)
        );
        assert_eq!(
            RENEWAL.lookup_beside(Some((&left, ends_at)), began),
            ProviderLookup::FewerThan(left.clone())
        );

        // Forty seconds before the regular replacement, the next early one
        // would be a minute away: the regular one comes first.
        let late = began + Duration::from_secs(470);
        assert_eq!(
            RENEWAL.next_replacement(&left, ends_at, late, 6) - began,
            Duration::from_secs(510)
        );
        // Once the regular replacement is due, a failure is retried on the
        // regular schedule, and the replacement may leave what the child left.
        let due = began + Duration::from_secs(510);
        assert_eq!(
            RENEWAL.next_replacement(&left, ends_at, due, 7) - due,
            Duration::from_secs(15)
        );
        assert_eq!(
            RENEWAL.lookup_beside(Some((&left, ends_at)), due),
            ProviderLookup::NoFewerThan(left.clone())
        );
    }
}
