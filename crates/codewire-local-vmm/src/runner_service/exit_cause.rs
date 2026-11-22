//! How a runner's process ended, kept with the error code its exit gave
//! (#4953): the exit status, and its name in that process's own exit-code
//! table.

use crate::control::v1;
use crate::diagnostic_log::LogField;
use crate::egress_broker::EgressBrokerStartupFailure;
use crate::mesh_process::MeshTransportStartupFailure;
use crate::network_worker::NetworkWorkerStartupFailure;
use crate::process_end::ProcessEnd;
use crate::runner::ExitClass;

/// The error code an exit puts the runner in.
pub(super) fn runner_exit_error_code(exit: ExitClass) -> Option<&'static str> {
    match exit {
        ExitClass::StillRunning => None,
        ExitClass::GuestShutdown => Some("guest_shutdown"),
        ExitClass::VmmFailure(_) => Some("vmm_exit"),
        ExitClass::DirectShareFailure(_) => Some("direct_share_exit"),
        ExitClass::NetworkWorkerFailure(_) => Some("network_worker_exit"),
        ExitClass::EgressBrokerFailure(_) => Some("egress_broker_exit"),
        ExitClass::IngressForwarderFailure => Some("ingress_forwarder_exit"),
        ExitClass::MeshTransportFailure(_) => Some("mesh_transport_exit"),
        ExitClass::MeshIngressReceiverFailure => Some("mesh_ingress_receiver_exit"),
    }
}

/// A process exit that put the runner in error: the code it gave, how the
/// process ended and its exit status's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ObservedExit {
    pub(super) code: &'static str,
    end: ProcessEnd,
    reason: Option<&'static str>,
}

/// The exit `exit` reports, when it is a process that ended with a status.
pub(super) fn observed_exit(exit: ExitClass) -> Option<ObservedExit> {
    let code = runner_exit_error_code(exit)?;
    let (end, reason) = match exit {
        ExitClass::VmmFailure(end) | ExitClass::DirectShareFailure(end) => (end, None),
        ExitClass::NetworkWorkerFailure(end) => (
            end,
            end.code()
                .and_then(NetworkWorkerStartupFailure::from_exit_code)
                .map(NetworkWorkerStartupFailure::runner_error_code),
        ),
        ExitClass::EgressBrokerFailure(end) => (
            end,
            end.code()
                .and_then(EgressBrokerStartupFailure::from_exit_code)
                .map(EgressBrokerStartupFailure::runner_error_code),
        ),
        ExitClass::MeshTransportFailure(end) => (
            end,
            end.code()
                .and_then(MeshTransportStartupFailure::from_exit_code)
                .map(MeshTransportStartupFailure::runner_error_code),
        ),
        ExitClass::StillRunning
        | ExitClass::GuestShutdown
        | ExitClass::IngressForwarderFailure
        | ExitClass::MeshIngressReceiverFailure => return None,
    };
    Some(ObservedExit { code, end, reason })
}

impl super::RunnerState {
    /// How the failed process ended, while the runner is still in the error
    /// its exit gave.
    pub(super) fn reported_exit(&self) -> Option<v1::RunnerExit> {
        self.exit
            .and_then(|exit| exit.reported_for(self.error_code))
    }
}

impl ObservedExit {
    /// As `RunnerInfo` carries it, while the runner's error code is `code`.
    pub(super) fn reported_for(self, code: Option<&'static str>) -> Option<v1::RunnerExit> {
        (code == Some(self.code)).then(|| v1::RunnerExit {
            status: self.end.code(),
            reason: self.reason.unwrap_or_default().to_owned(),
            signal: self.end.signal(),
        })
    }

    /// As the runner's log names it: `code_72_egress_broker_protocol`,
    /// `code_1`, `signal_9`.
    pub(super) fn log_field(self) -> LogField<'static> {
        LogField::Exit(self.end, self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sidecar_exit_is_named_from_its_own_exit_code_table() {
        let exit = observed_exit(ExitClass::EgressBrokerFailure(ProcessEnd::Code(72))).unwrap();
        assert_eq!(
            exit.reported_for(Some("egress_broker_exit")),
            Some(v1::RunnerExit {
                status: Some(72),
                reason: "egress_broker_protocol".to_owned(),
                signal: None,
            })
        );
    }

    #[test]
    fn an_unknown_status_or_a_signal_keeps_what_is_known() {
        let unknown =
            observed_exit(ExitClass::NetworkWorkerFailure(ProcessEnd::Code(250))).unwrap();
        assert_eq!(
            unknown.reported_for(Some("network_worker_exit")).unwrap(),
            v1::RunnerExit {
                status: Some(250),
                reason: String::new(),
                signal: None,
            }
        );
        let signalled = observed_exit(ExitClass::VmmFailure(ProcessEnd::Signal(9))).unwrap();
        assert_eq!(
            signalled.reported_for(Some("vmm_exit")).unwrap(),
            v1::RunnerExit {
                status: None,
                reason: String::new(),
                signal: Some(9),
            }
        );
    }

    /// Only an exit of a process with a status is kept, and only while the
    /// runner's error is still the code that exit gave.
    #[test]
    fn an_exit_is_reported_only_for_its_own_error_code() {
        assert_eq!(observed_exit(ExitClass::StillRunning), None);
        assert_eq!(observed_exit(ExitClass::GuestShutdown), None);
        assert_eq!(observed_exit(ExitClass::IngressForwarderFailure), None);
        let exit = observed_exit(ExitClass::MeshTransportFailure(ProcessEnd::Code(1))).unwrap();
        assert_eq!(exit.reported_for(None), None);
        assert_eq!(exit.reported_for(Some("vmm_start_failed")), None);
    }
}
