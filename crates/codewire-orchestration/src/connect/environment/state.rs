//! Environment states between the wire and storage.

use buffa::EnumValue;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::{AppError, AppResult};

use super::invalid_stored_value;

pub(super) fn api_environment_state(
    state: EnumValue<proto::EnvironmentState>,
) -> AppResult<String> {
    let value = match state.as_known() {
        Some(proto::EnvironmentState::Unspecified) => "",
        Some(proto::EnvironmentState::Pending) => "pending",
        Some(proto::EnvironmentState::PendingBuild) => "pending_build",
        Some(proto::EnvironmentState::Building) => "building",
        Some(proto::EnvironmentState::BuildFailed) => "build_failed",
        Some(proto::EnvironmentState::PullingSnapshot) => "pulling_snapshot",
        Some(proto::EnvironmentState::Creating) => "creating",
        Some(proto::EnvironmentState::Starting) => "starting",
        Some(proto::EnvironmentState::Running) => "running",
        Some(proto::EnvironmentState::Stopping) => "stopping",
        Some(proto::EnvironmentState::Stopped) => "stopped",
        Some(proto::EnvironmentState::Archiving) => "archiving",
        Some(proto::EnvironmentState::Archived) => "archived",
        Some(proto::EnvironmentState::Restoring) => "restoring",
        Some(proto::EnvironmentState::Resizing) => "resizing",
        Some(proto::EnvironmentState::Destroying) => "destroying",
        Some(proto::EnvironmentState::Destroyed) => "destroyed",
        Some(proto::EnvironmentState::Error) => "error",
        Some(proto::EnvironmentState::Unknown) => "unknown",
        None => return Err(AppError::BadRequest("unknown environment state".into())),
    };
    Ok(value.into())
}

pub(super) fn proto_environment_state(state: &str) -> AppResult<proto::EnvironmentState> {
    match state {
        "pending" => Ok(proto::EnvironmentState::Pending),
        "pending_build" => Ok(proto::EnvironmentState::PendingBuild),
        "building" => Ok(proto::EnvironmentState::Building),
        "build_failed" => Ok(proto::EnvironmentState::BuildFailed),
        "pulling_snapshot" => Ok(proto::EnvironmentState::PullingSnapshot),
        "creating" => Ok(proto::EnvironmentState::Creating),
        "starting" => Ok(proto::EnvironmentState::Starting),
        "running" => Ok(proto::EnvironmentState::Running),
        "stopping" => Ok(proto::EnvironmentState::Stopping),
        "stopped" => Ok(proto::EnvironmentState::Stopped),
        "archiving" => Ok(proto::EnvironmentState::Archiving),
        "archived" => Ok(proto::EnvironmentState::Archived),
        "restoring" => Ok(proto::EnvironmentState::Restoring),
        "resizing" => Ok(proto::EnvironmentState::Resizing),
        "destroying" => Ok(proto::EnvironmentState::Destroying),
        "destroyed" => Ok(proto::EnvironmentState::Destroyed),
        "error" => Ok(proto::EnvironmentState::Error),
        "unknown" => Ok(proto::EnvironmentState::Unknown),
        unexpected => invalid_stored_value("environment state", unexpected),
    }
}

/// The state a startup script was saved in (#5949).
pub(super) fn proto_scriptable_state(
    state: crate::api::environment_startup_script::ScriptableState,
) -> proto::EnvironmentState {
    use crate::api::environment_startup_script::ScriptableState;
    match state {
        ScriptableState::Running => proto::EnvironmentState::Running,
        ScriptableState::Stopped => proto::EnvironmentState::Stopped,
    }
}
