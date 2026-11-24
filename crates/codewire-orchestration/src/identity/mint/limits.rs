//! Minting's own request limits (docs/dev/SANDBOX-IDENTITY.md, "Minting"),
//! apart from the binding's ([`crate::workspace_binding::limits`]), so mints
//! can't starve binding renewals. Each refusal is `resource_exhausted`.
//!
//! Where each applies:
//!
//! - **Per Sandbox** and **per replica**, before any TokenReview. The
//!   Sandbox's bucket is its caller's address: authentication accepts a call
//!   only from the bound Pod's own address, so every call that can succeed
//!   for a Sandbox comes from that address, and a flood from it spends only
//!   its own bucket. The Sandbox's bucket is charged first, so its flood
//!   never spends the replica's.
//! - **The TokenReview semaphore**, around the review.
//! - **Per organization**, once the Sandbox's organization is known: after
//!   the review and the binding, and before the cache and any signature.
//!   Nothing before the review names the organization.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::workspace_binding::limits::RateLimiter;

/// 30 a minute, burst 10.
pub const SANDBOX_PER_SECOND: f64 = 30.0 / 60.0;
pub const SANDBOX_BURST: f64 = 10.0;
/// 3,000 a minute. The burst is a third of that, as the Sandbox's is.
pub const ORG_PER_SECOND: f64 = 3_000.0 / 60.0;
pub const ORG_BURST: f64 = 1_000.0;
/// 500 a second, with a second's worth at once.
pub const REPLICA_PER_SECOND: f64 = 500.0;
pub const REPLICA_BURST: f64 = 500.0;
pub const MAX_REVIEWS_IN_FLIGHT: usize = 16;
pub const REVIEW_SLOT_WAIT: Duration = Duration::from_secs(1);
/// Buckets tracked at once. A Sandbox's bucket is full again 20 seconds
/// after its last mint and is then dropped first.
pub const MAX_TRACKED_SANDBOXES: usize = 16 * 1024;
pub const MAX_TRACKED_ORGS: usize = 4 * 1024;

pub(crate) struct MintLimits {
    sandboxes: RateLimiter<IpAddr>,
    orgs: RateLimiter<String>,
    replica: RateLimiter<()>,
    reviews: Arc<Semaphore>,
}

impl Default for MintLimits {
    fn default() -> Self {
        Self {
            sandboxes: RateLimiter::new(SANDBOX_PER_SECOND, SANDBOX_BURST, MAX_TRACKED_SANDBOXES),
            orgs: RateLimiter::new(ORG_PER_SECOND, ORG_BURST, MAX_TRACKED_ORGS),
            replica: RateLimiter::new(REPLICA_PER_SECOND, REPLICA_BURST, 1),
            reviews: Arc::new(Semaphore::new(MAX_REVIEWS_IN_FLIGHT)),
        }
    }
}

impl MintLimits {
    /// The per-Sandbox, then the per-replica limit, for a call from `peer`.
    pub(crate) fn admit_peer(&self, peer: IpAddr) -> bool {
        let now = Instant::now();
        self.sandboxes.try_take(peer, now) && self.replica.try_take((), now)
    }

    pub(crate) fn admit_org(&self, org_id: &str) -> bool {
        self.orgs.try_take(org_id.to_owned(), Instant::now())
    }

    /// A TokenReview slot of minting's own, or `None` when none frees within
    /// [`REVIEW_SLOT_WAIT`].
    pub(crate) async fn review_slot(&self) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(REVIEW_SLOT_WAIT, self.reviews.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }

    #[cfg(test)]
    pub(crate) fn with(
        sandbox: (f64, f64),
        org: (f64, f64),
        replica: (f64, f64),
        reviews: usize,
    ) -> Self {
        Self {
            sandboxes: RateLimiter::new(sandbox.0, sandbox.1, MAX_TRACKED_SANDBOXES),
            orgs: RateLimiter::new(org.0, org.1, MAX_TRACKED_ORGS),
            replica: RateLimiter::new(replica.0, replica.1, 1),
            reviews: Arc::new(Semaphore::new(reviews)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 0, 9));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 0, 10));

    #[test]
    fn a_sandbox_gets_its_burst_of_ten_then_one_every_two_seconds() {
        let limits = MintLimits::default();
        for call in 0..10 {
            assert!(limits.admit_peer(A), "call {call}");
        }
        assert!(!limits.admit_peer(A));
        // Another Sandbox is unaffected.
        assert!(limits.admit_peer(B));
        let start = Instant::now();
        assert!(
            !limits
                .sandboxes
                .try_take(A, start + Duration::from_millis(1_900))
        );
        assert!(
            limits
                .sandboxes
                .try_take(A, start + Duration::from_millis(2_100))
        );
    }

    #[test]
    fn an_organization_gets_three_thousand_a_minute() {
        let limits = MintLimits::default();
        let start = Instant::now();
        for _ in 0..1_000 {
            assert!(limits.orgs.try_take("org-a".to_owned(), start));
        }
        assert!(!limits.orgs.try_take("org-a".to_owned(), start));
        assert!(limits.orgs.try_take("org-b".to_owned(), start));
        // 50 a second after the burst: 3,000 a minute.
        let minute = start + Duration::from_secs(60);
        let mut granted = 0;
        while limits.orgs.try_take("org-a".to_owned(), minute) {
            granted += 1;
        }
        assert_eq!(
            granted, 1_000,
            "a minute refills to the burst, never past it"
        );
    }

    #[test]
    fn a_replica_gets_five_hundred_a_second() {
        let limits = MintLimits::default();
        let start = Instant::now();
        let granted = (0..600)
            .filter(|_| limits.replica.try_take((), start))
            .count();
        assert_eq!(granted, 500);
        assert!(
            limits
                .replica
                .try_take((), start + Duration::from_millis(2))
        );
    }

    #[test]
    fn a_sandbox_over_its_limit_spends_nothing_of_the_replicas() {
        let limits = MintLimits::with((0.0, 1.0), (0.0, 1.0), (0.0, 2.0), 1);
        assert!(limits.admit_peer(A));
        for _ in 0..5 {
            assert!(!limits.admit_peer(A));
        }
        assert!(
            limits.admit_peer(B),
            "the replica still has its second call"
        );
        assert!(!limits.admit_peer(IpAddr::V4(Ipv4Addr::new(10, 244, 0, 11))));
    }

    #[tokio::test]
    async fn review_slots_are_minting_s_own_and_bounded() {
        let limits = MintLimits::with((1.0, 1.0), (1.0, 1.0), (1.0, 1.0), 1);
        let held = limits.review_slot().await.unwrap();
        let started = Instant::now();
        assert!(limits.review_slot().await.is_none());
        assert!(started.elapsed() >= REVIEW_SLOT_WAIT);
        drop(held);
        assert!(limits.review_slot().await.is_some());
        assert_eq!(MintLimits::default().reviews.available_permits(), 16);
    }
}
