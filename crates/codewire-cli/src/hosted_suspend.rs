//! The hosted daemon's suspend in a standard VM (#5529,
//! `docs/dev/IDLE-STOP.md`, "Suspend"): the platform connections it holds
//! closed, and the pause it asks the Pod's runtime for over vsock.

use std::sync::Arc;

use codewire_daemon::suspend::{Pending, SuspendPlatform};
use codewire_workspace_access::quiet::PlatformQuiet;

use crate::hosted_binding::BindingClient;

/// A wake report is tried this many times, this far apart: 20 s in all.
const WAKE_REPORT_ATTEMPTS: u32 = 5;
const WAKE_REPORT_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

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
