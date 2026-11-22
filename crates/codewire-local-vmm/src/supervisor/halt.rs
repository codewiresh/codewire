//! When the supervisor stops itself, and how (#2978, #3143), and the one log
//! line that says why (#5144).

use super::{Supervisor, SupervisorError, SupervisorStoreError, lifecycle_failure_cause};
use crate::diagnostic_log::{self, LogField};

impl Supervisor {
    /// Stop after a fatal error (#2978): no later commit or drain proceeds
    /// in any environment, and the supervisor shuts down. The log says why
    /// first: the process then exits 0, and without that line its log would
    /// end at the last effect.
    pub(super) fn halt(&self, reason: HaltReason<'_>) {
        self.record_halt(reason);
        self.core().store.stop();
        let _ = self.shutdown.send(true);
    }

    /// Writes the `supervisor_halted` line. A poisoned state lock stops the
    /// store itself, so it records through this without [`Self::halt`].
    pub(super) fn record_halt(&self, reason: HaltReason<'_>) {
        let (reason, class) = reason.names();
        diagnostic_log::record(
            self.log.as_deref(),
            "supervisor_halted",
            &[
                ("reason", LogField::Name(reason)),
                ("class", LogField::Name(class)),
            ],
        );
    }
}

/// Why the supervisor stops itself. An error is named by its class alone,
/// never its text.
pub(super) enum HaltReason<'a> {
    DrainError(&'a SupervisorError),
    RuntimeRecoveryError(&'a SupervisorError),
    PanickedTask,
    PoisonedLock,
}

impl HaltReason<'_> {
    /// The `reason` and `class` names the log line carries, with `none` where
    /// no error is at hand.
    fn names(&self) -> (&'static str, &'static str) {
        match self {
            Self::DrainError(error) => ("drain_error", lifecycle_failure_cause(error)),
            Self::RuntimeRecoveryError(error) => {
                ("runtime_recovery_error", lifecycle_failure_cause(error))
            }
            Self::PanickedTask => ("panicked_task", "none"),
            Self::PoisonedLock => ("poisoned_lock", "none"),
        }
    }
}

/// Whether a drain's error stops the supervisor, as an operation error always
/// has (#3143). A recovery waiting for the credential authority stops only its
/// name's drain until a later request retries it, and a retiring or stopping
/// supervisor is already ending.
pub(super) fn fatal_drain_error(error: &SupervisorError) -> bool {
    !matches!(
        error,
        SupervisorError::CredentialAuthorityUnavailable
            | SupervisorError::Retiring
            | SupervisorError::Store(SupervisorStoreError::Stopping)
    )
}
