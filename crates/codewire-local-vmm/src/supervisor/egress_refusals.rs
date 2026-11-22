//! `GetEgressRefusals` (#5058): a running VM's refusal log, read from its
//! runner for the owner's socket only. A VM that isn't running answers
//! FAILED_PRECONDITION, and no other failure does, so a client can say
//! which it was.

use super::*;

/// How long the read waits for the VM's runner.
const RUNNER_REFUSALS_TIMEOUT: Duration = Duration::from_secs(2);

fn not_running() -> Status {
    Status::failed_precondition(SupervisorError::NotRunning.to_string())
}

impl SupervisorRpc {
    pub(super) async fn egress_refusals(
        &self,
        selector: v1::EnvironmentSelector,
    ) -> Result<v1::EgressRefusals, Status> {
        let name = selected_name(selector)?;
        self.start_drains()?;
        let environment = self
            .supervisor
            .environment(&name)
            .map_err(|error| match error {
                SupervisorError::NotFound(_) => Status::from(error),
                other => Status::internal(other.to_string()),
            })?;
        if environment.state != StoredEnvironmentState::Running {
            return Err(not_running());
        }
        let socket = self.supervisor.config.runner_socket(environment.id);
        let unavailable = || Status::unavailable("the VM's runner did not answer");
        let read = tokio::time::timeout(RUNNER_REFUSALS_TIMEOUT, async {
            let mut client = RunnerClient::connect(&socket)
                .await
                .map_err(|_| unavailable())?;
            client
                .egress_refusals(environment.id, environment.generation)
                .await
        })
        .await
        .map_err(|_| unavailable())?;
        match read {
            Ok(refusals) => Ok(refusals),
            Err(status) if status.code() == tonic::Code::FailedPrecondition => Err(not_running()),
            Err(_) => Err(unavailable()),
        }
    }
}
