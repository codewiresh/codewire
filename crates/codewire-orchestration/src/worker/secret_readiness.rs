//! Cached readiness of the tenant-secret KEK authority.
//!
//! Kubelet probes `/readyz` every few seconds under a short deadline, while
//! verifying the persisted Transit canary costs several OpenBao round trips
//! across the network, plus a TokenRequest and an OpenBao login whenever the
//! short-lived OpenBao token is refreshed. Running that inside the probe let
//! any brief OpenBao or network stall withdraw the only orchestration Pod
//! from its Service (#2430).
//!
//! One background loop per Pod (not only the leader: readiness is per Pod)
//! verifies the canary, and the probe reads its latest verdict. The verdict
//! fails closed. The Pod is not ready before a verification succeeds, after
//! any verification fails or times out, or once the last success is older
//! than the freshness bound. A verification that is merely in flight keeps
//! the previous verdict, so a slow OpenBao round trip no longer fails the
//! probe on its own.
//!
//! `codewire_tenant_secret_readiness_verify_seconds` records every
//! verification by outcome, so stalls on the OpenBao path stay attributable
//! without failing readiness.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::FutureExt as _;
use prometheus::{HistogramOpts, HistogramVec, register_histogram_vec};

/// Timing for the background verification loop.
#[derive(Clone, Copy, Debug)]
pub struct SecretReadinessPolicy {
    /// Wait after a successful verification before the next one.
    pub interval: Duration,
    /// Wait after a failed verification before retrying.
    pub retry_interval: Duration,
    /// Upper bound for one verification.
    pub timeout: Duration,
    /// Age after which a success no longer counts, measured from the start
    /// of the verification that succeeded. It exceeds `interval` plus twice
    /// `timeout`, so two consecutive slow but successful verifications never
    /// let the earlier success expire.
    pub freshness: Duration,
    /// Verifications at least this slow are logged.
    pub slow: Duration,
}

impl Default for SecretReadinessPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            retry_interval: Duration::from_secs(5),
            timeout: Duration::from_secs(20),
            freshness: Duration::from_secs(60),
            slow: Duration::from_secs(1),
        }
    }
}

/// The latest tenant-secret readiness verdict, shared with `/readyz`.
#[derive(Clone)]
pub struct SecretReadiness {
    freshness: Duration,
    verdict: Arc<Mutex<Verdict>>,
}

#[derive(Default)]
struct Verdict {
    last_success: Option<Instant>,
    failed: bool,
}

#[derive(Clone, Copy)]
enum Outcome {
    Ready,
    Failed,
    TimedOut,
    Panicked,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Panicked => "panicked",
        }
    }
}

impl SecretReadiness {
    fn new(freshness: Duration) -> Self {
        Self {
            freshness,
            verdict: Arc::new(Mutex::new(Verdict::default())),
        }
    }

    /// Start the verification loop and return the verdict it maintains. The
    /// first verification starts immediately.
    pub fn spawn<F, Fut>(policy: SecretReadinessPolicy, verify: F) -> Self
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let readiness = Self::new(policy.freshness);
        tokio::spawn(readiness.clone().run(policy, verify));
        readiness
    }

    /// Whether the KEK authority was verified recently and has not failed
    /// since.
    pub fn is_ready(&self) -> bool {
        self.is_ready_at(Instant::now())
    }

    fn is_ready_at(&self, now: Instant) -> bool {
        let verdict = self.verdict.lock().unwrap();
        !verdict.failed
            && verdict
                .last_success
                .is_some_and(|at| now.saturating_duration_since(at) <= self.freshness)
    }

    /// Record a verification's result. A success counts from `started`, when
    /// the verification began observing the authority, not when it returned.
    fn record(&self, succeeded: bool, started: Instant) {
        let mut verdict = self.verdict.lock().unwrap();
        verdict.failed = !succeeded;
        if succeeded {
            verdict.last_success = Some(started);
        }
    }

    async fn run<F, Fut>(self, policy: SecretReadinessPolicy, verify: F)
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        loop {
            let started = Instant::now();
            // A panic must not end the loop: the last verdict would then
            // expire and never recover while `/healthz` keeps the Pod alive.
            let verification = AssertUnwindSafe(verify()).catch_unwind();
            let outcome = match tokio::time::timeout(policy.timeout, verification).await {
                Ok(Ok(Ok(()))) => Outcome::Ready,
                Ok(Ok(Err(error))) => {
                    tracing::warn!(%error, "tenant secret dependency is not ready");
                    Outcome::Failed
                }
                Ok(Err(_)) => {
                    tracing::error!("tenant secret readiness verification panicked");
                    Outcome::Panicked
                }
                Err(_) => Outcome::TimedOut,
            };
            let elapsed = started.elapsed();
            verify_seconds_metric()
                .with_label_values(&[outcome.as_str()])
                .observe(elapsed.as_secs_f64());
            if elapsed >= policy.slow {
                tracing::warn!(
                    outcome = outcome.as_str(),
                    elapsed_ms = elapsed.as_millis() as u64,
                    "tenant secret readiness verification was slow"
                );
            }
            let succeeded = matches!(outcome, Outcome::Ready);
            self.record(succeeded, started);
            tokio::time::sleep(if succeeded {
                policy.interval
            } else {
                policy.retry_interval
            })
            .await;
        }
    }
}

static VERIFY_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

/// From a warm round trip through a full token refresh to the timeout.
const VERIFY_BUCKETS: [f64; 10] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0];

fn verify_seconds_metric() -> &'static HistogramVec {
    VERIFY_SECONDS.get_or_init(|| {
        register_histogram_vec!(
            HistogramOpts::new(
                "codewire_tenant_secret_readiness_verify_seconds",
                "Duration of background tenant-secret KEK canary verifications, by outcome",
            )
            .buckets(VERIFY_BUCKETS.to_vec()),
            &["outcome"]
        )
        .expect("register tenant secret readiness histogram")
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::future::BoxFuture;
    use tokio::sync::{Mutex as AsyncMutex, mpsc};

    use super::*;

    #[test]
    fn default_policy_outlasts_a_slow_successful_verification() {
        let policy = SecretReadinessPolicy::default();
        assert!(policy.freshness > policy.interval + 2 * policy.timeout);
        assert!(policy.retry_interval <= policy.interval);
    }

    #[test]
    fn verdict_fails_closed_until_a_fresh_success() {
        let readiness = SecretReadiness::new(Duration::from_secs(60));
        let start = Instant::now();
        assert!(!readiness.is_ready_at(start), "no verification yet");

        readiness.record(true, start);
        assert!(readiness.is_ready_at(start));
        assert!(readiness.is_ready_at(start + Duration::from_secs(60)));
        assert!(
            !readiness.is_ready_at(start + Duration::from_secs(61)),
            "a success older than the freshness bound no longer counts"
        );

        let later = start + Duration::from_secs(10);
        readiness.record(false, later);
        assert!(
            !readiness.is_ready_at(later),
            "a failure withdraws readiness despite an earlier fresh success"
        );
        readiness.record(true, later);
        assert!(readiness.is_ready_at(later));
    }

    /// A verifier whose results the test hands out one at a time. While the
    /// test withholds a result, the loop's verification is in flight.
    fn scripted_verifier() -> (
        mpsc::UnboundedSender<anyhow::Result<()>>,
        impl Fn() -> BoxFuture<'static, anyhow::Result<()>> + Send + 'static,
    ) {
        let (results, receiver) = mpsc::unbounded_channel();
        let receiver = Arc::new(AsyncMutex::new(receiver));
        let verify = move || -> BoxFuture<'static, anyhow::Result<()>> {
            let receiver = receiver.clone();
            Box::pin(async move {
                receiver
                    .lock()
                    .await
                    .recv()
                    .await
                    .unwrap_or_else(|| Err(anyhow::anyhow!("script ended")))
            })
        };
        (results, verify)
    }

    async fn wait_until(condition: impl Fn() -> bool, what: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what} never happened"));
    }

    fn quick_policy() -> SecretReadinessPolicy {
        SecretReadinessPolicy {
            interval: Duration::ZERO,
            retry_interval: Duration::ZERO,
            timeout: Duration::from_secs(60),
            freshness: Duration::from_secs(60),
            slow: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn loop_keeps_the_last_success_while_a_verification_is_in_flight() {
        let (results, verify) = scripted_verifier();
        let readiness = SecretReadiness::spawn(quick_policy(), verify);
        assert!(
            !readiness.is_ready(),
            "not ready before the first verification"
        );

        results.send(Ok(())).unwrap();
        wait_until(|| readiness.is_ready(), "first success").await;

        // The next verification is now in flight with no result: a stalled
        // OpenBao round trip. The previous success still counts.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(readiness.is_ready());

        results
            .send(Err(anyhow::anyhow!("authority mismatch")))
            .unwrap();
        wait_until(|| !readiness.is_ready(), "failure").await;

        results.send(Ok(())).unwrap();
        wait_until(|| readiness.is_ready(), "recovery").await;
    }

    #[tokio::test]
    async fn loop_survives_a_panicking_verification() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let readiness = SecretReadiness::spawn(quick_policy(), {
            let calls = calls.clone();
            move || {
                let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if call == 0 {
                        panic!("verification bug");
                    }
                    Ok(())
                }
            }
        });
        wait_until(|| readiness.is_ready(), "recovery after a panic").await;
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn loop_records_a_timed_out_verification_as_a_failure() {
        // Keep the sender alive and send nothing: the channel never closes,
        // so only the timeout can end a verification.
        let (_results, verify) = scripted_verifier();
        let readiness = SecretReadiness::spawn(
            SecretReadinessPolicy {
                timeout: Duration::from_millis(20),
                ..quick_policy()
            },
            verify,
        );
        wait_until(
            || readiness.verdict.lock().unwrap().failed,
            "timed-out verification",
        )
        .await;
        assert!(!readiness.is_ready());
    }
}
