//! A local environment daemon's status as the public API reports it. Moved
//! out of `public_api.rs` unchanged (#5529).

use super::*;

pub(super) fn fixed_daemon_status(
    state: proto::EnvironmentDaemonState,
    message: &'static str,
) -> proto::EnvironmentDaemonStatus {
    proto::EnvironmentDaemonStatus {
        state: state.into(),
        protocol_version: DAEMON_PROTOCOL_VERSION,
        minimum_protocol_version: DAEMON_MINIMUM_PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        message: message.to_owned(),
        diagnostics: vec![proto::EnvironmentDaemonDiagnostic {
            name: "daemon".to_owned(),
            healthy: state == proto::EnvironmentDaemonState::Ready,
            message: message.to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub(super) fn project_daemon_status(
    capabilities: &daemon_v1::GetCapabilitiesResponse,
    health: &daemon_v1::GetHealthResponse,
) -> proto::EnvironmentDaemonStatus {
    let reported = capabilities
        .capabilities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let admitted = REQUIRED_LOCAL_DAEMON_CAPABILITIES
        .iter()
        .filter(|capability| reported.contains(**capability))
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    let protocol_compatible = capabilities.minimum_protocol_version <= DAEMON_PROTOCOL_VERSION
        && capabilities.protocol_version >= DAEMON_PROTOCOL_VERSION;
    let bundle_compatible = capabilities.daemon_version == env!("CARGO_PKG_VERSION");
    let capability_state = daemon_state(capabilities.state);
    let mut state = if !protocol_compatible || !bundle_compatible {
        proto::EnvironmentDaemonState::UpgradeRequired
    } else if capability_state == proto::EnvironmentDaemonState::Ready
        && admitted.len() != REQUIRED_LOCAL_DAEMON_CAPABILITIES.len()
    {
        proto::EnvironmentDaemonState::Unsupported
    } else if capability_state == proto::EnvironmentDaemonState::Ready {
        daemon_state(health.state)
    } else {
        capability_state
    };
    if state == proto::EnvironmentDaemonState::Unspecified {
        state = proto::EnvironmentDaemonState::Unhealthy;
    }
    let message = daemon_state_message(state);
    proto::EnvironmentDaemonStatus {
        state: state.into(),
        protocol_version: capabilities.protocol_version,
        minimum_protocol_version: capabilities.minimum_protocol_version,
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: admitted,
        message: message.to_owned(),
        diagnostics: vec![proto::EnvironmentDaemonDiagnostic {
            name: "daemon".to_owned(),
            healthy: state == proto::EnvironmentDaemonState::Ready,
            message: message.to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn daemon_state(value: i32) -> proto::EnvironmentDaemonState {
    match daemon_v1::DaemonState::try_from(value).unwrap_or(daemon_v1::DaemonState::Unspecified) {
        daemon_v1::DaemonState::Unspecified => proto::EnvironmentDaemonState::Unspecified,
        daemon_v1::DaemonState::Unsupported => proto::EnvironmentDaemonState::Unsupported,
        daemon_v1::DaemonState::Starting => proto::EnvironmentDaemonState::Starting,
        daemon_v1::DaemonState::Ready => proto::EnvironmentDaemonState::Ready,
        daemon_v1::DaemonState::Unhealthy => proto::EnvironmentDaemonState::Unhealthy,
        daemon_v1::DaemonState::UpgradeRequired => proto::EnvironmentDaemonState::UpgradeRequired,
    }
}

fn daemon_state_message(state: proto::EnvironmentDaemonState) -> &'static str {
    match state {
        proto::EnvironmentDaemonState::Unspecified | proto::EnvironmentDaemonState::Unhealthy => {
            "local environment daemon is unhealthy"
        }
        proto::EnvironmentDaemonState::Unsupported => {
            "local environment daemon is missing required capabilities"
        }
        proto::EnvironmentDaemonState::Starting => "local environment daemon is starting",
        proto::EnvironmentDaemonState::Ready => "local environment daemon is ready",
        proto::EnvironmentDaemonState::UpgradeRequired => {
            "local environment daemon bundle is incompatible"
        }
    }
}
