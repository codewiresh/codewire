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
/// Guest init's sleep-control Unix-socket relay inside a hosted `standard`
/// container (`codewire_vmm_guest_probe::hosted_control::HOSTED_SLEEP_CONTROL_SOCKET_PATH`).
#[cfg(any(target_os = "linux", test))]
const HOSTED_SLEEP_RELAY_SOCKET: &str = "/run/codewire-hosted/sleep/control.sock";
#[cfg(any(target_os = "linux", test))]
const HOSTED_CHECK_FROZEN_REQUEST: &[u8] = b"check-frozen\n";
#[cfg(any(target_os = "linux", test))]
const HOSTED_CHECK_FROZEN_ACCEPTED: &[u8] = b"ok\n";
#[cfg(any(target_os = "linux", test))]
const HOSTED_CHECK_FROZEN_TIMEOUT: Duration = Duration::from_millis(500);

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

/// Whether this process sits in the frozen workload cgroup (`/workload`), so
/// the runtime freezes it before pausing the VM and thaws it only after
/// delivering renewed tokens.
pub fn in_frozen_workload_process() -> bool {
    in_frozen_workload(Path::new(OWN_CGROUPS))
}

/// Whether this process sits in the frozen workload: the hierarchy that
/// carries the freezer places it at or under `/workload`.
///
/// Under `CODEWIRE_WORKSPACE_INIT=systemd`, container PID 1 calls
/// `unshare(CLONE_NEWCGROUP)` while inside cgroup v1 `/workload/workspace`,
/// which virtualizes `/proc/self/cgroup`'s freezer path to `/`. When the
/// freezer line reads `/` on Linux, fall back to asking guest init's
/// sleep-control relay (`HOSTED_SLEEP_RELAY_SOCKET`) via `check-frozen\n`;
/// guest init runs in the root cgroup namespace and checks our `SO_PEERCRED`
/// PID against `/proc/<pid>/cgroup`. Any missing socket, refusal, or error
/// fails closed (`false`).
pub(crate) fn in_frozen_workload(own_cgroups: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        in_frozen_workload_with_relay(own_cgroups, Path::new(HOSTED_SLEEP_RELAY_SOCKET))
    }
    #[cfg(not(target_os = "linux"))]
    {
        in_frozen_workload_direct(own_cgroups) == FreezerPathMatch::InWorkload
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreezerPathMatch {
    InWorkload,
    VirtualizedRoot,
    Outside,
}

fn in_frozen_workload_direct(own_cgroups: &Path) -> FreezerPathMatch {
    let Ok(cgroups) = std::fs::read_to_string(own_cgroups) else {
        return FreezerPathMatch::Outside;
    };
    let mut saw_root = false;
    for line in cgroups.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !controllers
            .split(',')
            .any(|controller| controller == "freezer")
        {
            continue;
        }
        if path == FROZEN_WORKLOAD
            || path
                .strip_prefix(FROZEN_WORKLOAD)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return FreezerPathMatch::InWorkload;
        }
        if path == "/" {
            saw_root = true;
        }
    }
    if saw_root {
        FreezerPathMatch::VirtualizedRoot
    } else {
        FreezerPathMatch::Outside
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn in_frozen_workload_with_relay(own_cgroups: &Path, relay_socket: &Path) -> bool {
    match in_frozen_workload_direct(own_cgroups) {
        FreezerPathMatch::InWorkload => true,
        FreezerPathMatch::VirtualizedRoot => query_sleep_relay_frozen(relay_socket),
        FreezerPathMatch::Outside => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn query_sleep_relay_frozen(relay_socket: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixStream;

        let Ok(mut stream) = UnixStream::connect(relay_socket) else {
            return false;
        };
        if stream
            .set_read_timeout(Some(HOSTED_CHECK_FROZEN_TIMEOUT))
            .is_err()
            || stream
                .set_write_timeout(Some(HOSTED_CHECK_FROZEN_TIMEOUT))
                .is_err()
        {
            return false;
        }
        if stream.write_all(HOSTED_CHECK_FROZEN_REQUEST).is_err() || stream.flush().is_err() {
            return false;
        }
        let mut answer = [0_u8; 3];
        if stream.read_exact(&mut answer).is_err() {
            return false;
        }
        answer == HOSTED_CHECK_FROZEN_ACCEPTED
    }
    #[cfg(not(unix))]
    {
        let _ = relay_socket;
        false
    }
}

#[cfg(test)]
mod tests;
