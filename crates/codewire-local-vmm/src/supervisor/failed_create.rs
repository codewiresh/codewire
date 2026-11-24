//! Removing what a create that failed left behind.

use super::{OperationRecord, Supervisor, SupervisorError};
use crate::diagnostic_log;

impl Supervisor {
    /// A failed create leaves nothing behind (#2491). Once the environment
    /// is recorded, the create fails in the same transaction that begins the
    /// ordinary delete of that environment, which then runs at once. The
    /// create keeps its own error code; the delete records its own outcome,
    /// so a delete that cannot finish leaves a visible `error` environment
    /// and a failed delete, never a silent record or a false "removed". The
    /// one thing kept is the runner's log of the failed start.
    pub(super) async fn roll_back_failed_create(
        &self,
        failed: &OperationRecord,
        name: &str,
        error_code: &str,
        recovering: bool,
    ) -> Result<(), SupervisorError> {
        let rollback = self
            .core()
            .fail_create_and_begin_rollback(failed, name, error_code)?;
        match rollback {
            Some(rollback) => {
                // Before the delete, which removes a log still under the
                // runner's name: what the failed start said is kept (#5238).
                if let Some(environment_id) = rollback.environment_id {
                    diagnostic_log::keep_failed_create_log(&self.root, environment_id, name);
                }
                self.run_delete_operation(name, &rollback, recovering).await
            }
            None => Ok(()),
        }
    }

    /// Completes a create that succeeded. A failed-create log kept under this
    /// name from an earlier attempt no longer describes it, so it goes.
    pub(super) fn complete_create(
        &self,
        operation: &OperationRecord,
        result: &serde_json::Value,
        name: &str,
    ) -> Result<(), SupervisorError> {
        self.core().complete_operation(operation, result)?;
        diagnostic_log::remove_log(&self.root, &diagnostic_log::failed_create_log_name(name));
        Ok(())
    }
}
