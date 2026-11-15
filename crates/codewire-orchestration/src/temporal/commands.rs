//! The environment workflow's command checks.

use super::EnvironmentCommand;
use crate::worker::activity_authority::AuthorityLost;

pub(super) fn known_environment_action(action: &str) -> bool {
    matches!(
        action,
        "create"
            | "start"
            | "stop"
            | "destroy"
            | "resize"
            | "restart_sources"
            | "reconcile"
            | "retry_setup"
    )
}

pub(super) fn ensure_workflow_environment(
    expected: &mut Option<String>,
    command: &EnvironmentCommand,
) -> anyhow::Result<()> {
    if command.environment_id.trim().is_empty() {
        return Err(AuthorityLost.into());
    }
    match expected {
        Some(environment_id) if environment_id != &command.environment_id => {
            Err(AuthorityLost.into())
        }
        Some(_) => Ok(()),
        slot @ None => {
            *slot = Some(command.environment_id.clone());
            Ok(())
        }
    }
}
