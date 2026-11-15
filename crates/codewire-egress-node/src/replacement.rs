//! How often one guest may start an egress stream (#4000).
//!
//! cw-egress will call [`StartLimiter::allow`] when a stream arrives (P2b),
//! before it reads the hello or asks orchestration to admit it, so a refused
//! start costs orchestration nothing: no TokenReview, no Pod read.
//! Orchestration already applies the same limit in `Admit`, before it
//! reviews the guest's token. The key is the
//! stream's TCP peer address, the one fact cw-egress knows first-hand; the
//! hello's token is not read, let alone trusted, until orchestration reviews
//! it. A workload in a guest can read its Pod's token and so open streams of
//! its own; closing one before opening the next does not get round the
//! limit, because every start counts.
//!
//! Which admitted stream a newer one replaces is decided afterwards, by the
//! admitted Pod's UID; each replacement is logged by the caller.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Stream starts allowed per peer address within [`START_WINDOW`].
pub const STARTS_PER_WINDOW: usize = 10;
pub const START_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct StartLimiter {
    recent: HashMap<IpAddr, Vec<Instant>>,
}

impl StartLimiter {
    /// Records a start from `peer` and says whether it may go on. Peers with
    /// no start inside the window are forgotten, so the map holds only peers
    /// that streamed recently.
    pub fn allow(&mut self, peer: IpAddr, now: Instant) -> bool {
        self.recent.retain(|_, starts| {
            starts.retain(|at| now.saturating_duration_since(*at) < START_WINDOW);
            !starts.is_empty()
        });
        let starts = self.recent.entry(peer).or_default();
        if starts.len() >= STARTS_PER_WINDOW {
            return false;
        }
        starts.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn peer(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 92, 4, last))
    }

    #[test]
    fn every_start_counts_so_closing_first_does_not_get_round_the_limit() {
        let mut limiter = StartLimiter::default();
        let now = Instant::now();
        for _ in 0..STARTS_PER_WINDOW {
            assert!(limiter.allow(peer(7), now));
        }
        assert!(!limiter.allow(peer(7), now));
        assert!(limiter.allow(peer(8), now), "per peer address");
    }

    #[test]
    fn a_limited_peer_starts_again_once_the_window_passes() {
        let mut limiter = StartLimiter::default();
        let now = Instant::now();
        for _ in 0..STARTS_PER_WINDOW {
            limiter.allow(peer(7), now);
        }
        assert!(!limiter.allow(peer(7), now + START_WINDOW - Duration::from_secs(1)));
        assert!(limiter.allow(peer(7), now + START_WINDOW));
    }

    #[test]
    fn quiet_peers_are_forgotten_and_a_busy_one_stays_limited() {
        let mut limiter = StartLimiter::default();
        let now = Instant::now();
        limiter.allow(peer(1), now);
        let busy = now + START_WINDOW;
        for _ in 0..STARTS_PER_WINDOW {
            limiter.allow(peer(2), busy);
        }
        assert!(!limiter.allow(peer(2), busy));
        assert!(!limiter.recent.contains_key(&peer(1)));
        assert!(limiter.recent.contains_key(&peer(2)));
    }
}
