//! Local endpoint advertisement cache.
//!
//! This mirrors the relevant Tailscale magicsock endpoint tracker behavior:
//! recently advertised endpoints remain visible through short netcheck/STUN
//! flaps, but stale endpoint churn is bounded per IP address.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// How long a previously seen endpoint remains advertised after it is absent.
///
/// Tailscale uses 5 minutes + 10 seconds, slightly longer than a full netcheck
/// period.
pub const ENDPOINT_TRACKER_LIFETIME: Duration = Duration::from_secs(5 * 60 + 10);

/// Maximum cached endpoints per IP address.
///
/// This keeps repeated STUN remaps from growing the advertised endpoint set
/// without bound.
pub const ENDPOINT_TRACKER_MAX_PER_ADDR: usize = 6;

#[derive(Debug, Default)]
pub struct EndpointTracker {
    endpoints: HashMap<IpAddr, Vec<EndpointEntry>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointEntry {
    endpoint: SocketAddr,
    until: Instant,
}

impl EndpointTracker {
    /// Return `current` plus non-expired cached endpoints.
    pub fn update(&mut self, current: Vec<SocketAddr>) -> Vec<SocketAddr> {
        self.update_at(Instant::now(), current)
    }

    /// Deterministic variant used by tests.
    pub fn update_at(&mut self, now: Instant, current: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let current_set = current.iter().copied().collect::<HashSet<_>>();
        let until = now + ENDPOINT_TRACKER_LIFETIME;

        for endpoint in &current {
            self.extend(*endpoint, until);
        }
        self.remove_expired(now);
        for endpoint in &current {
            self.add(now, *endpoint, until);
        }

        let mut out = current;
        let mut cached = self
            .endpoints
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|entry| !current_set.contains(&entry.endpoint))
            .filter(|entry| entry.until >= now)
            .map(|entry| entry.endpoint)
            .collect::<Vec<_>>();
        cached.sort_by_key(|endpoint| endpoint.to_string());
        out.extend(cached);
        out
    }

    fn extend(&mut self, endpoint: SocketAddr, until: Instant) {
        let Some(entries) = self.endpoints.get_mut(&endpoint.ip()) else {
            return;
        };
        if let Some(entry) = entries.iter_mut().find(|entry| entry.endpoint == endpoint) {
            entry.until = until;
        }
    }

    fn add(&mut self, now: Instant, endpoint: SocketAddr, until: Instant) {
        let entries = self.endpoints.entry(endpoint.ip()).or_default();
        if !entries.iter().any(|entry| entry.endpoint == endpoint) {
            entries.push(EndpointEntry { endpoint, until });
        }
        entries.retain(|entry| entry.until >= now);
        entries.sort_by_key(|entry| entry.until);
        while entries.len() > ENDPOINT_TRACKER_MAX_PER_ADDR {
            entries.remove(0);
        }
    }

    fn remove_expired(&mut self, now: Instant) {
        self.endpoints.retain(|_, entries| {
            entries.retain(|entry| entry.until >= now);
            !entries.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn sorted(mut endpoints: Vec<SocketAddr>) -> Vec<SocketAddr> {
        endpoints.sort_by_key(|endpoint| endpoint.to_string());
        endpoints
    }

    #[test]
    fn preserves_recent_endpoints_through_short_flaps() {
        let local = addr("192.168.1.1:12345");
        let stun4_1 = addr("1.2.3.4:12345");
        let stun4_2 = addr("5.6.7.8:12345");
        let stun6_1 = addr("[2a09:8280:1::1111]:12345");
        let stun6_2 = addr("[2a09:8280:1::2222]:12345");
        let start = Instant::now();
        let mut tracker = EndpointTracker::default();

        let steps = [
            (
                start,
                vec![local, stun4_1, stun6_1],
                vec![local, stun4_1, stun6_1],
            ),
            (
                start + Duration::from_secs(60),
                vec![local, stun4_1, stun6_1],
                vec![local, stun4_1, stun6_1],
            ),
            (
                start + Duration::from_secs(2 * 60),
                vec![local, stun6_1],
                vec![local, stun4_1, stun6_1],
            ),
            (
                start + Duration::from_secs(3 * 60),
                vec![local, stun4_1],
                vec![local, stun4_1, stun6_1],
            ),
            (
                start + Duration::from_secs(4 * 60),
                vec![local, stun4_2, stun6_2],
                vec![local, stun4_1, stun4_2, stun6_1, stun6_2],
            ),
            (
                start + Duration::from_secs(3 * 60) + ENDPOINT_TRACKER_LIFETIME
                    - Duration::from_secs(1),
                vec![local],
                vec![local, stun4_1, stun4_2, stun6_2],
            ),
            (
                start
                    + Duration::from_secs(4 * 60)
                    + ENDPOINT_TRACKER_LIFETIME
                    + Duration::from_secs(1),
                vec![local, stun4_2, stun6_2],
                vec![local, stun4_2, stun6_2],
            ),
            (
                start
                    + Duration::from_secs(4 * 60)
                    + ENDPOINT_TRACKER_LIFETIME
                    + Duration::from_secs(60),
                vec![local],
                vec![local, stun4_2, stun6_2],
            ),
        ];

        for (now, current, want) in steps {
            assert_eq!(sorted(tracker.update_at(now, current)), sorted(want));
        }
    }

    #[test]
    fn caps_cached_endpoints_per_ip_address() {
        let start = Instant::now();
        let mut tracker = EndpointTracker::default();
        let mut all = Vec::new();

        for i in 0..=ENDPOINT_TRACKER_MAX_PER_ADDR {
            let endpoint = addr(&format!("1.2.3.4:{}", 10000 + i));
            all.push(endpoint);
            tracker.update_at(start + Duration::from_secs(i as u64), vec![endpoint]);
        }

        let fresh_a = addr("1.2.3.4:10100");
        let fresh_b = addr("1.2.3.4:10101");
        all.push(fresh_a);
        all.push(fresh_b);
        let got = tracker.update_at(start + Duration::from_secs(60), vec![fresh_a, fresh_b]);
        let want = all[all.len() - ENDPOINT_TRACKER_MAX_PER_ADDR..].to_vec();
        assert_eq!(sorted(got), sorted(want));

        let input = (0..ENDPOINT_TRACKER_MAX_PER_ADDR + 5)
            .map(|i| addr(&format!("1.2.3.4:{}", 10200 + i)))
            .collect::<Vec<_>>();
        let got = tracker.update_at(start + Duration::from_secs(120), input.clone());
        assert_eq!(sorted(got), sorted(input));
    }
}
