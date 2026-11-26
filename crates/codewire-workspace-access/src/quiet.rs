//! Holding a hosted daemon's platform connections closed while it suspends
//! (#5529, `docs/dev/IDLE-STOP.md`, "Suspend"). Their far ends send periodic
//! traffic that would wake a paused VM, so a suspending daemon ends them and
//! dials none until it releases them at the wake.

use std::sync::Arc;

use codewire_tailnet::derp_transport::DerpHold;
use tokio::sync::watch;

/// The hold on a daemon's coordinator sessions (the tailnet's, and the Mesh
/// membership's) and on the tailnet's DERP connection. It starts released.
#[derive(Clone, Debug)]
pub struct PlatformQuiet {
    held: Arc<watch::Sender<bool>>,
    derp: DerpHold,
}

impl PlatformQuiet {
    pub fn new() -> Self {
        Self {
            held: Arc::new(watch::Sender::new(false)),
            derp: DerpHold::new(),
        }
    }

    /// Ends the coordinator sessions and the DERP connection, and dials none
    /// of them until [`Self::release`].
    pub fn hold(&self) {
        self.held.send_replace(true);
        self.derp.hold();
    }

    /// Redials what [`Self::hold`] ended.
    pub fn release(&self) {
        self.derp.release();
        self.held.send_replace(false);
    }

    pub fn derp(&self) -> &DerpHold {
        &self.derp
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.held.subscribe()
    }
}

impl Default for PlatformQuiet {
    fn default() -> Self {
        Self::new()
    }
}

/// Waits for the hold. A hold whose every handle is gone is never set again,
/// so this never returns.
pub(crate) async fn until_held(quiet: &mut watch::Receiver<bool>) {
    if quiet.wait_for(|held| *held).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Waits for the hold's release; a hold whose every handle is gone is
/// released.
pub(crate) async fn until_released(quiet: &mut watch::Receiver<bool>) {
    let _ = quiet.wait_for(|held| !*held).await;
}
