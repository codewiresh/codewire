//! How the platform ends a sandbox's create, start or run on its own, by
//! `environments.error_code`, and the words its user reads.

/// `environments.error_code` of a running sandbox whose Pod failed, until it runs
/// again (#3772). Says nothing of why: that isn't known here.
pub const SANDBOX_STOPPED_ERROR_CODE: &str = "sandbox_stopped";
/// The user's message for [`SANDBOX_STOPPED_ERROR_CODE`]. A failed Pod leaves its
/// volume, and reconcile brings the sandbox back on it, so this is true of this
/// path only: a lost node is not this path.
pub const SANDBOX_STOPPED_MESSAGE: &str = "This sandbox stopped unexpectedly and is restarting. Its files are safe; running processes were lost.";
/// `environments.error_code` of a running sandbox whose runtime is being
/// replaced, until it runs again (#4311): it is `starting`, not `running`, while
/// no runtime serves it.
pub const SANDBOX_REPLACING_ERROR_CODE: &str = "sandbox_replacing";
/// The user's message for [`SANDBOX_REPLACING_ERROR_CODE`].
pub const SANDBOX_REPLACING_MESSAGE: &str = "This sandbox's runtime is being replaced and it is restarting. Its files are safe; running processes were lost.";
/// `environments.error_code` of a sandbox running again after either, until its
/// next start or stop: nothing else would tell its user their processes went.
pub const SANDBOX_RESTARTED_ERROR_CODE: &str = "sandbox_restarted";

/// `environments.error_code` of a create or start the cluster had no room for.
pub const NO_CAPACITY_ERROR_CODE: &str = "no_capacity";

/// `environments.error_code` of a create whose workspace container could not
/// start. Its `error_reason` carries the container, the kubelet's reason and
/// its message, which say whether the image or the node is at fault.
pub const CONTAINER_START_FAILED_ERROR_CODE: &str = "container_start_failed";

/// `environments.error_code` of a create whose Pod's front door doesn't serve
/// every host its selection needs (#6290). Its `error_reason` names them.
pub const FRONT_DOOR_HOSTS_UNSERVED_ERROR_CODE: &str = "front_door_hosts_unserved";

/// Why the platform ended a create that never ran, which nothing retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailedCreate {
    ContainerStart,
    FrontDoorHostsUnserved,
}

impl FailedCreate {
    pub(super) fn code_and_phase(self) -> (&'static str, &'static str) {
        match self {
            Self::ContainerStart => (
                CONTAINER_START_FAILED_ERROR_CODE,
                "lifecycle_container_start_failed",
            ),
            Self::FrontDoorHostsUnserved => (
                FRONT_DOOR_HOSTS_UNSERVED_ERROR_CODE,
                "lifecycle_front_door_hosts_unserved",
            ),
        }
    }
}

/// How a create or a start ends when the cluster has no room for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoCapacityRefusal {
    pub message: &'static str,
    pub state: &'static str,
    pub desired_state: &'static str,
}

impl NoCapacityRefusal {
    /// The create handler also resumes a start and retries an errored sandbox,
    /// so only one that never ran may be destroyed; any other keeps its files.
    pub fn for_create(never_ran: bool) -> Self {
        if never_ran { Self::CREATE } else { Self::START }
    }

    /// A create leaves nothing behind: the next reconcile destroys it through
    /// the normal destroy, and it stops counting against quota now.
    pub const CREATE: Self = Self {
        message: "No capacity right now. Try again shortly.",
        state: "error",
        desired_state: "destroyed",
    };
    /// A stopped sandbox's volume cannot leave its node, so it goes back to
    /// stopped, through the normal stop, with its files untouched.
    pub const START: Self = Self {
        message: "The node holding this sandbox is full. Its files are safe. Try again shortly.",
        state: "stopping",
        desired_state: "stopped",
    };
}

// ── Postgres store (port of pgstore.go, worker-used slice) ─────────────
