//! Request limits applied per orchestration replica, on top of the listener's
//! connection limits (design §3.6):
//!
//! - a peer-IP token bucket, checked before any TokenReview, so a flood is
//!   refused with `resource_exhausted` at no review cost;
//! - at most [`MAX_REVIEWS_IN_FLIGHT`] TokenReviews in flight, where waiting
//!   longer than [`REVIEW_SLOT_WAIT`] for a slot is `unavailable`;
//! - one request in flight per reviewed Pod UID;
//! - at most [`MAX_RELAY_PAIRS`] distinct peer relay pairs per environment,
//!   each counted for [`RELAY_PAIR_LIFETIME`] (#5962).

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Sustained requests per second from one peer IP.
pub const PEER_REQUESTS_PER_SECOND: f64 = 1.0;
/// Requests one idle peer IP may send at once.
pub const PEER_BURST: f64 = 5.0;
/// Peer buckets tracked at once. Past this, full (idle) buckets are dropped,
/// and a new peer is refused if every tracked peer is still limited.
pub const MAX_TRACKED_PEERS: usize = 4096;
pub const MAX_REVIEWS_IN_FLIGHT: usize = 16;
pub const REVIEW_SLOT_WAIT: Duration = Duration::from_secs(1);
/// Distinct disco-key pairs one environment may hold relay slots for.
pub const MAX_RELAY_PAIRS: usize = 32;
/// How long a pair counts: the relay's steady-state lifetime for a slot.
pub const RELAY_PAIR_LIFETIME: Duration = Duration::from_secs(300);
/// Environments whose pairs are tracked before expired ones are swept.
const MAX_TRACKED_RELAY_ENVIRONMENTS: usize = 4096;

/// All request limits of one replica.
pub struct RequestLimits {
    peers: PeerRateLimiter,
    reviews: Arc<Semaphore>,
    pods: PodSlots,
    relay_pairs: RelayPairs,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            peers: PeerRateLimiter::new(PEER_REQUESTS_PER_SECOND, PEER_BURST, MAX_TRACKED_PEERS),
            reviews: Arc::new(Semaphore::new(MAX_REVIEWS_IN_FLIGHT)),
            pods: PodSlots::default(),
            relay_pairs: RelayPairs::default(),
        }
    }
}

impl RequestLimits {
    pub fn allow_peer(&self, peer: IpAddr) -> bool {
        self.peers.try_take(peer, Instant::now())
    }

    /// A TokenReview slot, or `None` when none frees within the wait.
    pub async fn review_slot(&self) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(REVIEW_SLOT_WAIT, self.reviews.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }

    /// The only in-flight request for this reviewed Pod UID, or `None`.
    pub fn pod_slot(&self, pod_uid: &str) -> Option<PodSlot> {
        self.pods.try_acquire(pod_uid)
    }

    /// Counts `pair` against `environment`'s relay pairs: true when it is
    /// already counted or fits under [`MAX_RELAY_PAIRS`].
    pub fn take_relay_pair(&self, environment: &str, pair: [&str; 2]) -> bool {
        self.relay_pairs.try_take(environment, pair, Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn with_peer_burst(burst: f64) -> Self {
        Self {
            peers: PeerRateLimiter::new(PEER_REQUESTS_PER_SECOND, burst, MAX_TRACKED_PEERS),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn with_review_slots(slots: usize) -> Self {
        Self {
            reviews: Arc::new(Semaphore::new(slots)),
            ..Self::default()
        }
    }
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// Token bucket per peer IP.
pub type PeerRateLimiter = RateLimiter<IpAddr>;

/// Token bucket per key, tracking a bounded number of keys.
pub struct RateLimiter<K> {
    rate: f64,
    burst: f64,
    max_peers: usize,
    buckets: Mutex<HashMap<K, Bucket>>,
}

impl<K: Hash + Eq> RateLimiter<K> {
    pub fn new(rate: f64, burst: f64, max_peers: usize) -> Self {
        Self {
            rate,
            burst,
            max_peers,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn refill(&self, bucket: &mut Bucket, now: Instant) {
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.updated = now;
    }

    pub fn try_take(&self, peer: K, now: Instant) -> bool {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !buckets.contains_key(&peer) && buckets.len() >= self.max_peers {
            // A full bucket carries no state a fresh one would not.
            buckets.retain(|_, bucket| {
                self.refill(bucket, now);
                bucket.tokens < self.burst
            });
            if buckets.len() >= self.max_peers {
                return false;
            }
        }
        let bucket = buckets.entry(peer).or_insert(Bucket {
            tokens: self.burst,
            updated: now,
        });
        self.refill(bucket, now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The peer relay pairs each environment holds, with when each stops
/// counting. A pair is unordered, as the relay keys it.
#[derive(Default)]
struct RelayPairs(Mutex<HashMap<String, HashMap<[String; 2], Instant>>>);

impl RelayPairs {
    fn try_take(&self, environment: &str, pair: [&str; 2], now: Instant) -> bool {
        let mut pair = pair.map(str::to_owned);
        pair.sort();
        let mut environments = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !environments.contains_key(environment)
            && environments.len() >= MAX_TRACKED_RELAY_ENVIRONMENTS
        {
            environments.retain(|_, pairs| {
                pairs.retain(|_, until| *until > now);
                !pairs.is_empty()
            });
        }
        let pairs = environments.entry(environment.to_owned()).or_default();
        pairs.retain(|_, until| *until > now);
        if !pairs.contains_key(&pair) && pairs.len() >= MAX_RELAY_PAIRS {
            return false;
        }
        pairs.insert(pair, now + RELAY_PAIR_LIFETIME);
        true
    }
}

#[derive(Clone, Default)]
struct PodSlots(Arc<Mutex<HashSet<String>>>);

impl PodSlots {
    fn try_acquire(&self, pod_uid: &str) -> Option<PodSlot> {
        let mut pods = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pods.insert(pod_uid.to_owned()).then(|| PodSlot {
            pods: self.clone(),
            pod_uid: pod_uid.to_owned(),
        })
    }
}

/// Held for the life of one request; releases the Pod UID on drop.
pub struct PodSlot {
    pods: PodSlots,
    pod_uid: String,
}

impl Drop for PodSlot {
    fn drop(&mut self) {
        self.pods
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.pod_uid);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

    /// #5962: an environment holds at most 32 distinct pairs at once. A pair
    /// it already holds is free, in either order, and another environment
    /// has its own 32. A pair counts for 300 s.
    #[test]
    fn relay_pairs_cap_each_environment() {
        let pairs = RelayPairs::default();
        let start = Instant::now();
        let keys: Vec<String> = (0..=MAX_RELAY_PAIRS).map(|n| format!("peer-{n}")).collect();
        for key in &keys[..MAX_RELAY_PAIRS] {
            assert!(pairs.try_take("env-a", ["own", key], start));
        }
        let extra = keys[MAX_RELAY_PAIRS].as_str();
        assert!(!pairs.try_take("env-a", ["own", extra], start));
        assert!(pairs.try_take("env-a", [keys[0].as_str(), "own"], start));
        assert!(pairs.try_take("env-b", ["own", extra], start));

        let later = start + RELAY_PAIR_LIFETIME;
        assert!(pairs.try_take("env-a", ["own", extra], later));
    }

    #[test]
    fn peer_bucket_allows_the_burst_then_one_per_second() {
        let limiter = PeerRateLimiter::new(1.0, 5.0, 16);
        let start = Instant::now();
        for _ in 0..5 {
            assert!(limiter.try_take(PEER, start));
        }
        assert!(!limiter.try_take(PEER, start));
        assert!(!limiter.try_take(PEER, start + Duration::from_millis(900)));
        assert!(limiter.try_take(PEER, start + Duration::from_millis(1000)));
        assert!(!limiter.try_take(PEER, start + Duration::from_millis(1100)));
        // Another peer has its own bucket.
        assert!(limiter.try_take(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), start));
        // Refill never exceeds the burst.
        let later = start + Duration::from_secs(60);
        for _ in 0..5 {
            assert!(limiter.try_take(PEER, later));
        }
        assert!(!limiter.try_take(PEER, later));
    }

    #[test]
    fn tracked_peers_are_bounded_and_idle_buckets_are_dropped() {
        let limiter = PeerRateLimiter::new(1.0, 2.0, 2);
        let start = Instant::now();
        let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 0, 1, last));
        assert!(limiter.try_take(peer(1), start));
        assert!(limiter.try_take(peer(2), start));
        // Both tracked peers are still limited: a third is refused, not
        // given a fresh bucket that would reset the others.
        assert!(!limiter.try_take(peer(3), start));
        // Once the tracked peers have refilled, their buckets are dropped.
        assert!(limiter.try_take(peer(3), start + Duration::from_secs(5)));
        assert!(limiter.buckets.lock().unwrap().len() <= 2);
    }

    #[test]
    fn one_request_in_flight_per_pod() {
        let limits = RequestLimits::default();
        let slot = limits
            .pod_slot("7e7b20f6-0bd2-4f11-8b16-9c239851eb52")
            .unwrap();
        assert!(
            limits
                .pod_slot("7e7b20f6-0bd2-4f11-8b16-9c239851eb52")
                .is_none()
        );
        assert!(
            limits
                .pod_slot("a1560db3-8899-40c9-b521-500f223b04fb")
                .is_some()
        );
        drop(slot);
        assert!(
            limits
                .pod_slot("7e7b20f6-0bd2-4f11-8b16-9c239851eb52")
                .is_some()
        );
    }

    #[tokio::test]
    async fn review_slots_are_bounded_and_waiting_is_capped() {
        let limits = RequestLimits::with_review_slots(1);
        let held = limits.review_slot().await.unwrap();
        let started = Instant::now();
        assert!(limits.review_slot().await.is_none());
        assert!(started.elapsed() >= REVIEW_SLOT_WAIT);
        drop(held);
        assert!(limits.review_slot().await.is_some());
    }
}
