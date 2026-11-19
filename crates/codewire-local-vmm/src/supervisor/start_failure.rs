//! What a start the runner failed is reported as.

use tonic::Status;

use super::{SupervisorError, runner_event_error_code_valid};
use crate::control::v1;
use crate::runner_service;

/// How the runner ended a start it failed: its error code and, beside a
/// cause it inferred, what it saw.
pub(super) struct RunnerStartFailure {
    pub(super) error_code: String,
    observed: String,
}

impl RunnerStartFailure {
    pub(super) fn of(event: &v1::RunnerEvent) -> Self {
        Self {
            error_code: event.error_code.clone(),
            observed: event.error_observed.clone(),
        }
    }
}

/// The supervisor's error for a start its runner failed: the error of a
/// cause the runner names, else the runner's own words.
pub(super) fn runner_start_error(failure: &RunnerStartFailure, status: &Status) -> SupervisorError {
    let error_code = failure.error_code.as_str();
    if error_code == runner_service::CREDENTIAL_BROKER_UNAVAILABLE {
        // What the runner saw is one of its closed names; anything else
        // came from a runner this supervisor does not know.
        let observed = if runner_event_error_code_valid(&failure.observed) {
            failure.observed.clone()
        } else {
            "unknown".to_owned()
        };
        return SupervisorError::CredentialBrokerUnavailable { observed };
    }
    if error_code == runner_service::GUEST_DOCKER_TOOLING_MISSING {
        return SupervisorError::GuestDockerToolingMissing;
    }
    if error_code == runner_service::GUEST_SETUP_FAILED {
        return SupervisorError::GuestSetupFailed;
    }
    if error_code == runner_service::GUEST_WORKSPACE_FAILED {
        return SupervisorError::GuestWorkspaceFailed;
    }
    if error_code == runner_service::HOST_PORT_UNAVAILABLE {
        return SupervisorError::HostPortUnavailable;
    }
    if let Some(refusal) = crate::runner::InterceptRefusal::from_code(error_code) {
        return SupervisorError::Interception(refusal);
    }
    #[cfg(target_os = "macos")]
    if error_code == runner_service::VM_START_REFUSED {
        return SupervisorError::VmStartRefused;
    }
    SupervisorError::VmStart(status.message().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(error_code: &str, observed: &str) -> SupervisorError {
        runner_start_error(
            &RunnerStartFailure {
                error_code: error_code.to_owned(),
                observed: observed.to_owned(),
            },
            &Status::unavailable("the runner's own words"),
        )
    }

    #[test]
    fn a_broker_that_never_came_keeps_what_the_runner_saw() {
        let error = failed(
            runner_service::CREDENTIAL_BROKER_UNAVAILABLE,
            "egress_broker_exited",
        );
        assert!(matches!(
            &error,
            SupervisorError::CredentialBrokerUnavailable { observed } if observed == "egress_broker_exited"
        ));
        assert_eq!(
            error.to_string(),
            "the VM's credentials could not be served: its credential broker never connected (the VM's runner saw egress_broker_exited)"
        );
        // Only a closed name is kept; a runner's free text is not repeated.
        for unknown in ["", "Not A Name", "a-b"] {
            assert!(matches!(
                failed(runner_service::CREDENTIAL_BROKER_UNAVAILABLE, unknown),
                SupervisorError::CredentialBrokerUnavailable { observed } if observed == "unknown"
            ));
        }
    }

    #[test]
    fn every_other_code_is_reported_as_before() {
        assert!(matches!(
            failed(runner_service::GUEST_SETUP_FAILED, ""),
            SupervisorError::GuestSetupFailed
        ));
        assert!(matches!(
            failed("front_door_received_dead", ""),
            SupervisorError::Interception(_)
        ));
        // What the runner saw is read only beside the cause it belongs to.
        assert!(matches!(
            failed("guest_start_failed", "egress_broker_exited"),
            SupervisorError::VmStart(words) if words == "the runner's own words"
        ));
    }
}
