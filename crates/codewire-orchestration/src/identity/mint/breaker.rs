//! The global circuit breaker (docs/dev/SANDBOX-IDENTITY.md, "Kill
//! switches"): the operator's `CODEWIRE_IDENTITY_MINTING=off`, and an
//! automatic trip for [`TRIP_FOR`] after [`TRIP_AFTER_FAILURES`] consecutive
//! signing failures. While it is open every mint is `identity_unavailable`.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::identity::config::MintingSwitch;

pub const TRIP_AFTER_FAILURES: u32 = 20;
pub const TRIP_FOR: Duration = Duration::from_secs(60);

pub(crate) struct CircuitBreaker {
    switch: MintingSwitch,
    state: Mutex<Trip>,
}

#[derive(Default)]
struct Trip {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    pub(crate) fn new(switch: MintingSwitch) -> Self {
        Self {
            switch,
            state: Mutex::default(),
        }
    }

    /// Whether a mint may go ahead at `now`.
    pub(crate) fn allows(&self, now: Instant) -> bool {
        if self.switch == MintingSwitch::Off {
            return false;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.open_until {
            Some(until) if now < until => false,
            Some(_) => {
                state.open_until = None;
                true
            }
            None => true,
        }
    }

    /// A signature was made: the failure count starts again.
    pub(crate) fn signed(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .consecutive_failures = 0;
    }

    /// OpenBao couldn't read the key or sign. The failure that makes
    /// [`TRIP_AFTER_FAILURES`] in a row opens the breaker until `now +
    /// TRIP_FOR`, and the count starts again.
    pub(crate) fn failed(&self, now: Instant) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= TRIP_AFTER_FAILURES {
            state.consecutive_failures = 0;
            state.open_until = Some(now + TRIP_FOR);
            tracing::error!(
                failures = TRIP_AFTER_FAILURES,
                seconds = TRIP_FOR.as_secs(),
                "sandbox identity signing failed repeatedly; minting is stopped for a minute"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operators_switch_stops_every_mint() {
        let breaker = CircuitBreaker::new(MintingSwitch::Off);
        assert!(!breaker.allows(Instant::now()));
        breaker.signed();
        assert!(!breaker.allows(Instant::now() + TRIP_FOR * 10));
    }

    #[test]
    fn twenty_failures_in_a_row_trip_it_for_a_minute() {
        let breaker = CircuitBreaker::new(MintingSwitch::On);
        let start = Instant::now();
        for _ in 1..TRIP_AFTER_FAILURES {
            breaker.failed(start);
        }
        assert!(breaker.allows(start), "19 failures leave it closed");
        breaker.failed(start);
        assert!(!breaker.allows(start));
        assert!(!breaker.allows(start + TRIP_FOR - Duration::from_millis(1)));
        assert!(breaker.allows(start + TRIP_FOR));
        // The count started again at the trip.
        breaker.failed(start + TRIP_FOR);
        assert!(breaker.allows(start + TRIP_FOR));
    }

    #[test]
    fn a_signature_between_failures_resets_the_count() {
        let breaker = CircuitBreaker::new(MintingSwitch::On);
        let now = Instant::now();
        for _ in 1..TRIP_AFTER_FAILURES {
            breaker.failed(now);
        }
        breaker.signed();
        for _ in 1..TRIP_AFTER_FAILURES {
            breaker.failed(now);
        }
        assert!(breaker.allows(now));
    }
}
