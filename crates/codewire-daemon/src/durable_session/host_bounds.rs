//! Host sessions' wall-clock bounds, apart from the engine so that file,
//! past the size at which a file stops growing, loses a concern instead of
//! gaining lines.

use super::*;

/// Host sessions' wall-clock bounds, and a guest session's cleanup. Each one
/// that runs out leaves its outcome unknown, never retried.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HostBounds {
    /// A host process group's whole cleanup after its TERM grace:
    /// descendants settling after KILL, the leader's reap, and the control and
    /// output joins spend it together (#3777).
    pub(crate) cleanup: Duration,
    /// A guest session group's whole cleanup after its TERM grace, spent as
    /// [`Self::cleanup`] is.
    pub(crate) guest_cleanup: Duration,
    /// A host-control input's or stop's dispatch: queueing and the
    /// monitor's write and flush, or its whole cleanup. Host control is
    /// Linux only.
    #[cfg(target_os = "linux")]
    pub(crate) control_dispatch: Duration,
    /// The daemon's whole shutdown: its launches' cleanup, then every host
    /// session's pause and stop, together.
    pub(crate) shutdown: Duration,
    /// How long a host-control RPC waits for its request's outcome before it
    /// answers with the receipt it has. The request goes on either way. Zero,
    /// a test bound, answers at once with the receipt as admitted.
    #[cfg(target_os = "linux")]
    pub(crate) rpc_join: Duration,
}

impl HostBounds {
    pub(crate) const PRODUCT: Self = Self {
        cleanup: crate::host_process::CLEANUP_BUDGET,
        guest_cleanup: crate::host_process::GUEST_CLEANUP_BUDGET,
        #[cfg(target_os = "linux")]
        control_dispatch: SESSION_INPUT_TIMEOUT,
        shutdown: LAUNCH_SHUTDOWN_TIMEOUT,
        #[cfg(target_os = "linux")]
        rpc_join: HOST_CONTROL_RPC_JOIN,
    };

    /// Every host bound replaced by `bound`: the Linux host-control
    /// entrypoint's test seam and the tests' hang guard.
    #[cfg(target_os = "linux")]
    pub(crate) const fn all(bound: Duration) -> Self {
        Self {
            cleanup: bound,
            guest_cleanup: bound,
            #[cfg(target_os = "linux")]
            control_dispatch: bound,
            shutdown: bound,
            #[cfg(target_os = "linux")]
            rpc_join: bound,
        }
    }

    /// The product's bounds, except the two that only bound how long a
    /// caller waits for an outcome, the daemon's whole shutdown and a
    /// host-control RPC's join, which become `bound`. For a test whose
    /// subject may be a host session's own bounds but is never those waits.
    #[cfg(test)]
    pub(crate) const fn waits_within(bound: Duration) -> Self {
        Self {
            shutdown: bound,
            #[cfg(target_os = "linux")]
            rpc_join: bound,
            ..Self::PRODUCT
        }
    }

    /// [`Self::waits_within`], with both owners' cleanup budgets `bound`
    /// too. For a test whose subject is a stop's signals, not how long its
    /// cleanup may take, so a loaded runner does not end it as unknown
    /// (#6243).
    #[cfg(test)]
    pub(crate) const fn cleanup_within(bound: Duration) -> Self {
        Self {
            cleanup: bound,
            guest_cleanup: bound,
            ..Self::waits_within(bound)
        }
    }
}
