//! The runner error code a failed start reports, from the runner's error.

use super::*;

/// Name the prepare failures a user can fix without reading runner logs.
pub(super) fn prepare_error_code(error: &RunnerError) -> &'static str {
    match error {
        RunnerError::HostPortUnavailable(_) => HOST_PORT_UNAVAILABLE,
        RunnerError::Interception(refusal) => refusal.code(),
        _ => "prepare_failed",
    }
}

pub(super) fn network_start_error_code(error: &RunnerError) -> &'static str {
    match error {
        RunnerError::InvalidNetworkWorker => "network_worker_invalid",
        RunnerError::NetworkWorkerSpawn => "network_worker_spawn",
        RunnerError::NetworkWorkerStartTimeout => "network_worker_start_timeout",
        RunnerError::NetworkWorkerBootstrap => "network_worker_bootstrap",
        #[cfg(target_os = "macos")]
        RunnerError::VmStartRefused(_) => VM_START_REFUSED,
        RunnerError::GuestDockerToolingMissing => GUEST_DOCKER_TOOLING_MISSING,
        RunnerError::GuestSetupFailed => GUEST_SETUP_FAILED,
        RunnerError::GuestWorkspaceFailed => GUEST_WORKSPACE_FAILED,
        RunnerError::NetworkWorkerStartup(failure) => failure.runner_error_code(),
        RunnerError::NetworkWorkerWait => "network_worker_wait",
        RunnerError::NetworkWorkerKillTimeout => "network_worker_kill_timeout",
        RunnerError::HostPortUnavailable(_) => HOST_PORT_UNAVAILABLE,
        RunnerError::IngressControl => "ingress_forwarder_start",
        RunnerError::EgressPolicyControl => "egress_policy_control",
        RunnerError::EgressBrokerSpawn => "egress_broker_spawn",
        RunnerError::EgressBrokerStartTimeout => "egress_broker_start_timeout",
        RunnerError::EgressBrokerBootstrap => "egress_broker_bootstrap",
        RunnerError::Interception(refusal) => refusal.code(),
        RunnerError::EgressBrokerStartup(failure) => failure.runner_error_code(),
        RunnerError::EgressBrokerWait => "egress_broker_wait",
        RunnerError::EgressBrokerKillTimeout => "egress_broker_kill_timeout",
        RunnerError::FrontDoor(failure) => failure.runner_error_code(),
        RunnerError::MeshTransportSpawn => "mesh_transport_spawn",
        RunnerError::MeshTransportStartTimeout => "mesh_transport_start_timeout",
        RunnerError::MeshTransportBootstrap => "mesh_transport_bootstrap",
        RunnerError::MeshTransportStartup(failure) => failure.runner_error_code(),
        RunnerError::MeshEnrollmentBrokerSpawn => "mesh_enrollment_broker_spawn",
        RunnerError::MeshEnrollmentBrokerStartTimeout => "mesh_enrollment_broker_start_timeout",
        RunnerError::MeshEnrollmentBrokerBootstrap => "mesh_enrollment_broker_bootstrap",
        RunnerError::MeshEnrollmentBrokerStartup(failure) => failure.runner_error_code(),
        RunnerError::MeshProcessWait => "mesh_process_wait",
        RunnerError::MeshProcessKillTimeout => "mesh_process_kill_timeout",
        _ => "network_stack_failed",
    }
}

/// A workspace launch the guest's daemon refused before it ran (#6281).
pub(crate) const GUEST_WORKSPACE_LAUNCH_REFUSED: &str = "guest_workspace_launch_refused";

pub(super) fn guest_failure_detail(stage: GuestBootStage) -> &'static str {
    match stage {
        GuestBootStage::SetupFailed => GUEST_SETUP_FAILED,
        GuestBootStage::DockerToolingMissing => GUEST_DOCKER_TOOLING_MISSING,
        GuestBootStage::WorkspaceLaunchRefused => GUEST_WORKSPACE_LAUNCH_REFUSED,
        _ => GUEST_WORKSPACE_FAILED,
    }
}
