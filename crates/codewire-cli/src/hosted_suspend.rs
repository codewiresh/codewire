//! The hosted daemon's suspend in a standard VM (#5529,
//! `docs/dev/IDLE-STOP.md`, "Suspend"): the platform connections it holds
//! closed, and the pause it asks the Pod's runtime for over vsock.

use codewire_daemon::suspend::{Pending, SuspendPlatform};
use codewire_workspace_access::quiet::PlatformQuiet;

pub(crate) struct HostedSuspend {
    quiet: PlatformQuiet,
}

impl HostedSuspend {
    pub(crate) fn new(quiet: PlatformQuiet) -> Self {
        Self { quiet }
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
        // Orchestration's ReportWake comes with its suspended mark's loop;
        // until then nothing marks the Sandbox, so the wake is only logged.
        Box::pin(async {
            tracing::info!("the sandbox resumed from a suspend");
        })
    }
}
