//! The startup re-apply of broker Sandboxes' environment policies (#6070,
//! SPEC "egress lockdown check"). A release can change what
//! `cw-daemon-net-<env>` renders (the gateway, the UDP relay, the server
//! namespace, the key broker). The lockdown check compares the live policy
//! with the new rendering, so until each running broker Sandbox's policy is
//! applied again its next admission would be refused as `policy_differs`.
//! So at startup orchestration applies every bound broker Sandbox's policy
//! again (`worker::egress_reapply`), and until that sweep has finished, or
//! its bound has passed, the egress service answers every lockdown decision
//! with a retryable UNAVAILABLE instead of deciding. Admit itself still never
//! applies a policy: a difference found after the sweep is refused.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prometheus::{IntCounterVec, Opts, register_int_counter_vec};

/// The longest the sweep holds the egress service's decisions. Past it the
/// service decides anyway, and a Sandbox whose policy was not applied again
/// is refused, never admitted.
pub const SWEEP_BOUND: Duration = Duration::from_secs(60);

/// What one environment's re-apply found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyReapply {
    /// Its bound Sandbox is not whole broker, or none is bound: nothing to do.
    NotBroker,
    /// It has no policy, as a stopped environment has none: none is made.
    Absent,
    /// Its policy is already the rendered one.
    Current,
    /// Its policy was replaced with the rendered one.
    Applied,
}

impl PolicyReapply {
    /// The outcome as a log field: a closed set.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotBroker => "not_broker",
            Self::Absent => "absent",
            Self::Current => "current",
            Self::Applied => "applied",
        }
    }
}

static REAPPLIES: OnceLock<IntCounterVec> = OnceLock::new();

/// Count one environment's re-apply by its outcome. `applied` means the live
/// policy differed from the rendering: a release changed it, or someone did
/// between restarts.
pub fn count_reapply(outcome: PolicyReapply) {
    REAPPLIES
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "codewire_egress_policy_reapplies_total",
                    "Bound broker environments' policies the startup sweep checked, by outcome."
                ),
                &["outcome"]
            )
            .expect("egress re-apply metric registration must be unique")
        })
        .with_label_values(&[outcome.label()])
        .inc();
}

/// Whether the startup sweep has finished: until then the egress service
/// decides no lockdown.
#[derive(Debug, Default)]
pub struct PoliciesReapplied(AtomicBool);

impl PoliciesReapplied {
    /// A sweep still to run.
    pub fn pending() -> Arc<Self> {
        Arc::default()
    }

    /// Nothing to wait for: a process with no sweep to run.
    pub fn finished() -> Arc<Self> {
        let reapplied = Self::default();
        reapplied.finish();
        Arc::new(reapplied)
    }

    pub fn finish(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_finished(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
