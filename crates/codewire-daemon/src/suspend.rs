//! A hosted `standard` daemon's suspend (#5529, `docs/dev/IDLE-STOP.md`,
//! "Suspend"). The worker's `Suspend` holds the daemon's platform
//! connections closed, since their far ends send periodic traffic that would
//! wake a paused VM, ends the credential relay's open epoch and refuses new
//! ones, and is answered; then the daemon asks the Pod's runtime to pause the
//! VM. On `no`, or a request that fails, it releases them at once. After
//! `ok` it ticks every second: a tick more than [`WAKE_GAP`] of wall-clock
//! time after the one before means the VM was paused and has resumed, and
//! [`QUIET_TICKS`] ticks without one mean there was no pause, or one too
//! short to leave a gap. Either way it releases them and reports the wake.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use tonic::Status;

use crate::credential_bridge::CredentialBridge;

/// How long after answering the daemon waits before it asks for the pause,
/// so the answer reaches the worker before the workload freezes.
pub const ANSWER_LEAD: Duration = Duration::from_secs(1);
/// How often the daemon ticks while it waits for the pause and the wake.
pub const SUSPEND_TICK: Duration = Duration::from_secs(1);
/// A tick this much wall-clock time after the one before follows a pause.
pub const WAKE_GAP: Duration = Duration::from_secs(3);
/// After this many ticks without a gap the daemon is running again.
pub const QUIET_TICKS: u32 = 30;

/// Where a process reads its own cgroups.
const OWN_CGROUPS: &str = "/proc/self/cgroup";
/// The cgroup the runtime's freeze stops (the guest's `workload`).
const FROZEN_WORKLOAD: &str = "/workload";

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a suspend needs from the hosted daemon's process: its platform
/// connections, the Pod's runtime and orchestration.
pub trait SuspendPlatform: Send + Sync + 'static {
    /// Ends the coordinator sessions and the DERP connection and dials none
    /// until [`Self::release`].
    fn hold(&self);
    fn release(&self);
    /// Asks the Pod's runtime to pause the VM: `true` for `ok`, `false` for
    /// `no`.
    fn ask_pause(&self) -> Pending<'_, io::Result<bool>>;
    /// Tells orchestration the Sandbox is running again.
    fn report_wake(&self) -> Pending<'_, ()>;
}

static INSTALLED: OnceLock<Arc<dyn SuspendPlatform>> = OnceLock::new();

/// Makes this process's daemon suspend through `platform`. Only a hosted
/// daemon in a `standard` VM installs one; any other daemon answers
/// `Suspend` as unimplemented.
pub fn install(platform: Arc<dyn SuspendPlatform>) {
    if INSTALLED.set(platform).is_err() {
        tracing::warn!("a second suspend platform was ignored");
    }
}

pub(crate) fn installed() -> Option<Arc<dyn SuspendPlatform>> {
    INSTALLED.get().cloned()
}

pub(crate) struct Suspend {
    platform: Arc<dyn SuspendPlatform>,
    suspending: Arc<AtomicBool>,
    own_cgroups: PathBuf,
    wall_clock: fn() -> SystemTime,
}

impl Suspend {
    pub(crate) fn new(platform: Arc<dyn SuspendPlatform>) -> Self {
        Self {
            platform,
            suspending: Arc::default(),
            own_cgroups: PathBuf::from(OWN_CGROUPS),
            wall_clock: SystemTime::now,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_own_cgroups(mut self, path: &Path) -> Self {
        self.own_cgroups = path.to_owned();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_wall_clock(mut self, wall_clock: fn() -> SystemTime) -> Self {
        self.wall_clock = wall_clock;
        self
    }

    /// Starts a suspend and answers whether it started: not while one is
    /// under way. Refused outright when this daemon is outside the workload
    /// the runtime freezes, since only a frozen daemon dials nothing between
    /// the resume and the delivery of the tokens renewed meanwhile.
    pub(crate) async fn begin(&self, bridge: &CredentialBridge) -> Result<bool, Status> {
        if !in_frozen_workload(&self.own_cgroups) {
            return Err(Status::failed_precondition(
                "this daemon is not in the workload a pause freezes",
            ));
        }
        if self.suspending.swap(true, Ordering::SeqCst) {
            return Ok(false);
        }
        self.platform.hold();
        bridge.hold().await;
        tokio::spawn(run(
            Arc::clone(&self.platform),
            bridge.clone(),
            Arc::clone(&self.suspending),
            self.wall_clock,
        ));
        Ok(true)
    }
}

async fn run(
    platform: Arc<dyn SuspendPlatform>,
    bridge: CredentialBridge,
    suspending: Arc<AtomicBool>,
    wall_clock: fn() -> SystemTime,
) {
    tokio::time::sleep(ANSWER_LEAD).await;
    // The runtime pauses the VM straight after its answer, before this task
    // runs again, so the time before the pause is read before asking: read
    // after the answer, it already follows the resume and shows no gap.
    let before = wall_clock();
    let paused = match platform.ask_pause().await {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::warn!(error = %error, "the suspend request to the runtime failed");
            false
        }
    };
    if paused {
        wait_for_wake(wall_clock, before).await;
    }
    platform.release();
    bridge.release().await;
    if paused {
        platform.report_wake().await;
    }
    suspending.store(false, Ordering::SeqCst);
}

/// Returns at the first tick after a wall-clock gap since `last`, the time
/// read before the pause was asked for, or after [`QUIET_TICKS`] ticks
/// without one.
async fn wait_for_wake(wall_clock: fn() -> SystemTime, mut last: SystemTime) {
    let mut ticks = tokio::time::interval(SUSPEND_TICK);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticks.tick().await;
    for _ in 0..QUIET_TICKS {
        ticks.tick().await;
        let now = wall_clock();
        let gap = now.duration_since(last).unwrap_or_default();
        last = now;
        if gap > WAKE_GAP {
            tracing::info!(gap_ms = gap.as_millis(), "the VM resumed");
            return;
        }
    }
}

/// Whether this process sits in the frozen workload: the hierarchy that
/// carries the freezer places it at or under `/workload`.
fn in_frozen_workload(own_cgroups: &Path) -> bool {
    let Ok(cgroups) = std::fs::read_to_string(own_cgroups) else {
        return false;
    };
    cgroups.lines().any(|line| {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        controllers
            .split(',')
            .any(|controller| controller == "freezer")
            && (path == FROZEN_WORKLOAD
                || path
                    .strip_prefix(FROZEN_WORKLOAD)
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

#[cfg(test)]
mod tests;
