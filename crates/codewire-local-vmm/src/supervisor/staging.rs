//! The check that a drain leaves nothing staged beside an active workspace
//! without an operation that owns it (#2978).

use super::halt::{HaltReason, fatal_drain_error};
use super::{Supervisor, SupervisorCore, SupervisorError, runtime_move};
use crate::diagnostic_log::{self, LogField};

impl SupervisorCore {
    /// After `name`'s drain, nothing of it stays staged beside an active
    /// workspace. Only that name: another environment may be mid-update
    /// (#2978). Staging no operation owns refuses the request, says which
    /// environment, and records `drain_refused`; the supervisor keeps serving
    /// every environment (#5144). The same request is refused the same way
    /// until the environment is removed.
    pub(super) fn ensure_no_unowned_workspace_staging(
        &self,
        name: &str,
    ) -> Result<(), SupervisorError> {
        if let Some(environment) = self.state.environments.get(name).filter(|environment| {
            environment.active_workspace_generation.is_some()
                && environment.staging_workspace_generation.is_some()
                && !runtime_move::staged_runtime_move(environment)
        }) {
            diagnostic_log::record(
                self.log.as_deref(),
                "drain_refused",
                &[
                    ("environment", LogField::Id(environment.id)),
                    ("class", LogField::Name("unowned_workspace_staging")),
                ],
            );
            return Err(SupervisorError::UnownedWorkspaceStaging(name.to_owned()));
        }
        Ok(())
    }
}

impl Supervisor {
    /// [`Supervisor::drain_under`] for a delete's admission: unowned staging
    /// does not refuse it (#5144). The delete moves the VM's whole tree to
    /// trash, staged generation included, and nothing else clears that
    /// state. Every other drain error refuses or halts as for any request.
    pub(super) async fn drain_under_for_delete(
        &self,
        lease: tokio::sync::OwnedMutexGuard<()>,
        name: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, SupervisorError> {
        let name = name.to_owned();
        self.detached(|supervisor| async move {
            match supervisor.drain_held(&name).await {
                Ok(()) | Err(SupervisorError::UnownedWorkspaceStaging(_)) => Ok(lease),
                Err(error) => {
                    if fatal_drain_error(&error) {
                        supervisor.halt(HaltReason::DrainError(&error));
                    }
                    Err(error)
                }
            }
        })
        .await
    }
}
