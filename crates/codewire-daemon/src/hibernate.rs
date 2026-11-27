//! A hosted `standard` daemon's hibernate and post-restore re-bind
//! (#6647, `docs/dev/SANDBOX-SLEEP.md`).
//!
//! When the worker asks this daemon to hibernate:
//! 1. The daemon refuses outright if it is outside `/workload` (the cgroup
//!    the runtime freezes) or if a hibernate is already under way.
//! 2. It shuts down its old platform access (`2222`, tailnet, coordinator)
//!    and holds the credential bridge so open epochs end and none open.
//! 3. It asks the Pod's runtime to arm hibernate-on-SIGTERM. On refusal or
//!    error it releases the hold and keeps serving.
//! 4. On acceptance it wipes the old Pod's daemon credential from memory
//!    synchronously before returning `accepted = true` (so no further 7777
//!    RPC can pass with the old credential before freeze or after thaw),
//!    then closes pre-hibernate connections after [`ANSWER_LEAD`].
//! 5. After restore in the new Pod, the platform waits for the guest-probe's
//!    restore settings, binds as the new Pod's daemon, rotates the credential
//!    bridge to the new generation, installs the new daemon credential (only
//!    while the daemon is suspended for re-bind — a running daemon never
//!    re-binds), and signals `rebind-ok` to the Pod's runtime so Pod ports
//!    open and the memory file is deleted.

use std::future::Future;
use std::io;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use codewire_daemon_proto::DaemonAuthToken;
use tonic::Status;
use uuid::Uuid;

use crate::auth_rotation::DaemonAuth;
use crate::credential_bridge::CredentialBridge;

/// How long after answering `Hibernate` the daemon waits before aborting open
/// pre-hibernate connections, so the `accepted = true` frame reaches the
/// worker cleanly while no new RPC can be authorized.
pub const ANSWER_LEAD: Duration = Duration::from_millis(200);

/// Where a process reads its own cgroups.
const OWN_CGROUPS: &str = "/proc/self/cgroup";

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The new Pod's authority returned by `BindWorkspace` after a hibernate
/// restore (`docs/dev/SANDBOX-SLEEP.md`, "After a restore").
pub struct ReboundIdentity {
    pub daemon_credential: DaemonAuthToken,
    pub environment_id: Uuid,
    pub operation_generation: u64,
}

/// What a hibernate and post-restore re-bind need from the hosted daemon's
/// process: its access listeners/tailnet, the Pod's runtime, and binding.
pub trait HibernatePlatform: Send + Sync + 'static {
    /// Closes client access (`2222` and tailnet/coordinator sessions) before
    /// arming hibernate so no old tailnet session or key stays live.
    fn hold_for_hibernate(&self);

    /// Restores access when the Pod's runtime refuses hibernate or fails to
    /// answer, so the Sandbox continues running normally.
    fn release_on_refusal(&self);

    /// Asks the Pod's runtime to arm hibernate-on-SIGTERM: `true` for `ok`,
    /// `false` for `no`.
    fn ask_hibernate(&self) -> Pending<'_, io::Result<bool>>;

    /// Waits for the guest-probe's restore settings after the VM thaws in a
    /// new Pod, runs `BindWorkspace` for the new Pod, brings up the new
    /// Pod's access (`2222` + fresh tailnet node key), and returns the new
    /// Pod's daemon credential and binding generation.
    fn wait_for_restore_and_rebind(&self) -> Pending<'_, Result<ReboundIdentity, String>>;

    /// Tells the Pod's runtime that the restored daemon has re-bound and is
    /// serving with the new Pod's authority, so Pod ports open and the memory
    /// file is deleted.
    fn on_rebind_serving(&self) -> Pending<'_, ()>;
}

static INSTALLED: OnceLock<Arc<dyn HibernatePlatform>> = OnceLock::new();

/// Makes this process's daemon hibernate through `platform`. Only a hosted
/// daemon in a `standard` VM installs one; any other daemon answers
/// `Hibernate` as unimplemented.
pub fn install(platform: Arc<dyn HibernatePlatform>) {
    if INSTALLED.set(platform).is_err() {
        tracing::warn!("a second hibernate platform was ignored");
    }
}

pub(crate) fn installed() -> Option<Arc<dyn HibernatePlatform>> {
    INSTALLED.get().cloned()
}

pub(crate) struct Hibernate {
    platform: Arc<dyn HibernatePlatform>,
    hibernating: Arc<AtomicBool>,
    own_cgroups: PathBuf,
    answer_lead: Duration,
}

impl Hibernate {
    pub(crate) fn new(platform: Arc<dyn HibernatePlatform>) -> Self {
        Self {
            platform,
            hibernating: Arc::default(),
            own_cgroups: PathBuf::from(OWN_CGROUPS),
            answer_lead: ANSWER_LEAD,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_own_cgroups(mut self, path: &Path) -> Self {
        self.own_cgroups = path.to_owned();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_answer_lead(mut self, lead: Duration) -> Self {
        self.answer_lead = lead;
        self
    }

    /// Arms hibernate-on-SIGTERM in the Pod's runtime and prepares this
    /// daemon for post-restore re-bind. Refused outright outside `/workload`
    /// so only a daemon frozen by the runtime can hibernate.
    pub(crate) async fn begin(
        &self,
        auth: &DaemonAuth,
        bridge: &CredentialBridge,
    ) -> Result<bool, Status> {
        if !crate::suspend::in_frozen_workload(&self.own_cgroups) {
            return Err(Status::failed_precondition(
                "this daemon is not in the workload a hibernate freezes",
            ));
        }
        if self.hibernating.swap(true, Ordering::SeqCst) {
            return Ok(false);
        }

        self.platform.hold_for_hibernate();
        bridge.hold().await;

        let accepted = match self.platform.ask_hibernate().await {
            Ok(true) => true,
            Ok(false) => {
                self.platform.release_on_refusal();
                bridge.release().await;
                self.hibernating.store(false, Ordering::SeqCst);
                false
            }
            Err(error) => {
                tracing::warn!(error = %error, "the hibernate request to the runtime failed");
                self.platform.release_on_refusal();
                bridge.release().await;
                self.hibernating.store(false, Ordering::SeqCst);
                return Err(Status::unavailable(
                    "could not arm hibernate in the Pod runtime",
                ));
            }
        };

        if !accepted {
            return Ok(false);
        }

        // Wipe the old Pod's credential synchronously before returning
        // `accepted = true`, so no further 7777 RPC can be authorized under
        // the old Pod's credential before freeze or after thaw.
        auth.begin_hosted_rebind();

        tokio::spawn(run_rebind(
            Arc::clone(&self.platform),
            auth.clone(),
            bridge.clone(),
            Arc::clone(&self.hibernating),
            self.answer_lead,
        ));
        Ok(true)
    }
}

async fn run_rebind(
    platform: Arc<dyn HibernatePlatform>,
    auth: DaemonAuth,
    bridge: CredentialBridge,
    hibernating: Arc<AtomicBool>,
    answer_lead: Duration,
) {
    tokio::time::sleep(answer_lead).await;
    auth.end_pre_hibernate_connections();

    let rebound = match platform.wait_for_restore_and_rebind().await {
        Ok(rebound) => rebound,
        Err(error) => {
            tracing::error!(
                error = %error,
                "post-restore re-bind failed; leaving daemon closed"
            );
            return;
        }
    };

    if let Err(error) = bridge
        .rotate_identity_after_restore(rebound.environment_id, rebound.operation_generation)
        .await
    {
        tracing::error!(
            error = %error,
            "could not rotate credential bridge after hibernate restore; leaving daemon closed"
        );
        return;
    }

    if let Err(error) = auth.complete_hosted_rebind(rebound.daemon_credential) {
        tracing::error!(
            error = %error,
            "could not install restored daemon credential; leaving daemon closed"
        );
        return;
    }

    platform.on_rebind_serving().await;
    hibernating.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests;
