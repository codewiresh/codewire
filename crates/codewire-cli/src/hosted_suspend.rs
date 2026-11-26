//! The hosted daemon's suspend in a standard VM (#5529,
//! `docs/dev/IDLE-STOP.md`, "Suspend"): the platform connections it holds
//! closed, and the pause it asks the Pod's runtime for over vsock.

use std::sync::Arc;

use codewire_daemon::suspend::{Pending, SuspendPlatform};
use codewire_workspace_access::quiet::PlatformQuiet;

use crate::hosted_binding::BindingClient;
use crate::hosted_daemon::WarmPauseOutcome;

/// A wake report is tried this many times, this far apart: 20 s in all.
const WAKE_REPORT_ATTEMPTS: u32 = 5;
const WAKE_REPORT_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// How long an unbound `standard` warm-pool daemon waits after `pod-runtime`
/// accepts a suspend request (`ok` leaves before `freeze_and_pause`) so it
/// does not open a new `BindWorkspace` dial while the runtime is freezing its
/// cgroup. Once paused, `kvm-clock` carries time across the pause so this
/// finishes immediately upon wake.
const UNBOUND_PAUSE_SETTLE: std::time::Duration = std::time::Duration::from_millis(250);

/// Asks `pod-runtime` to pause this unbound `standard` warm-pool VM until a
/// claim wakes it on port 7777 (#5602). Refuses cleanly when the daemon is not
/// in the frozen `/workload` cgroup or when the runtime does not support
/// suspend.
pub(crate) fn pause_while_unbound()
-> std::pin::Pin<Box<dyn std::future::Future<Output = WarmPauseOutcome> + Send>> {
    Box::pin(async {
        if !codewire_daemon::suspend::in_frozen_workload_process() {
            tracing::debug!(
                "unbound standard daemon is not in the frozen workload cgroup; staying awake"
            );
            return WarmPauseOutcome::Unavailable;
        }
        tracing::info!("unbound standard warm-pool daemon pausing until claimed");
        match codewire_vmm_guest_probe::hosted_control::request_suspend().await {
            Ok(true) => {
                tokio::time::sleep(UNBOUND_PAUSE_SETTLE).await;
                tracing::info!(
                    "unbound standard warm-pool daemon resumed; polling for workspace binding"
                );
                WarmPauseOutcome::Paused
            }
            Ok(false) => {
                tracing::debug!("runtime refused unbound warm-pool suspend; staying awake");
                WarmPauseOutcome::Unavailable
            }
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    "unbound warm-pool suspend unavailable; staying awake"
                );
                WarmPauseOutcome::Unavailable
            }
        }
    })
}

pub(crate) struct HostedSuspend {
    quiet: PlatformQuiet,
    binding: Arc<BindingClient>,
}

impl HostedSuspend {
    pub(crate) fn new(quiet: PlatformQuiet, binding: Arc<BindingClient>) -> Self {
        Self { quiet, binding }
    }
}

impl SuspendPlatform for HostedSuspend {
    fn hold(&self) {
        self.quiet.hold();
    }

    fn release(&self) {
        self.quiet.release();
    }

    fn ask_pause(&self) -> Pending<'_, std::io::Result<bool>> {
        Box::pin(codewire_vmm_guest_probe::hosted_control::request_suspend())
    }

    fn report_wake(&self) -> Pending<'_, ()> {
        Box::pin(async {
            tracing::info!("the sandbox resumed from a suspend");
            // Liveness moves a resumed Sandbox whose daemon reported no wake
            // within 60 s to error, so a failed report is tried again well
            // inside that.
            for attempt in 1..=WAKE_REPORT_ATTEMPTS {
                match self.binding.report_wake().await {
                    Ok(()) => return,
                    Err(error) => {
                        tracing::warn!(attempt, error = ?error, "the wake report failed");
                    }
                }
                if attempt < WAKE_REPORT_ATTEMPTS {
                    tokio::time::sleep(WAKE_REPORT_RETRY).await;
                }
            }
        })
    }
}
