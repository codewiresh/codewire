//! The daemon's status, diagnostics and repair, in their wire form.

use super::*;

pub(super) fn proto_environment_daemon_repair(
    repair: ApiEnvironmentDaemonRepair,
) -> proto::RepairEnvironmentDaemonResponse {
    proto::RepairEnvironmentDaemonResponse {
        status: Some(proto_environment_daemon_status(repair.status)).into(),
        replaced_pod_name: repair.replaced_pod_name,
        ..Default::default()
    }
}

pub(super) fn proto_environment_daemon_status(
    status: ApiEnvironmentDaemonStatus,
) -> proto::EnvironmentDaemonStatus {
    proto::EnvironmentDaemonStatus {
        state: proto_environment_daemon_state(status.state).into(),
        protocol_version: status.protocol_version,
        minimum_protocol_version: status.minimum_protocol_version,
        daemon_version: status.daemon_version,
        capabilities: status.capabilities,
        message: status.message,
        diagnostics: status
            .diagnostics
            .into_iter()
            .map(proto_environment_daemon_diagnostic)
            .collect(),
        pod_name: status.pod_name,
        ..Default::default()
    }
}

fn proto_environment_daemon_diagnostic(
    diagnostic: ApiEnvironmentDaemonDiagnostic,
) -> proto::EnvironmentDaemonDiagnostic {
    proto::EnvironmentDaemonDiagnostic {
        name: diagnostic.name,
        healthy: diagnostic.healthy,
        message: diagnostic.message,
        ..Default::default()
    }
}

pub(super) fn proto_environment_daemon_state(
    state: codewire_daemon_proto::daemon::v1::DaemonState,
) -> proto::EnvironmentDaemonState {
    use codewire_daemon_proto::daemon::v1::DaemonState as Internal;
    match state {
        Internal::Unspecified => proto::EnvironmentDaemonState::Unspecified,
        Internal::Unsupported => proto::EnvironmentDaemonState::Unsupported,
        Internal::Starting => proto::EnvironmentDaemonState::Starting,
        Internal::Ready => proto::EnvironmentDaemonState::Ready,
        Internal::Unhealthy => proto::EnvironmentDaemonState::Unhealthy,
        Internal::UpgradeRequired => proto::EnvironmentDaemonState::UpgradeRequired,
    }
}
