//! Supervisor RPCs for suspending and resuming local Linux VMs (#5529,
//! protocol 30, `docs/dev/LOCAL-VM-SLEEP.md`).

use super::*;

impl SupervisorRpc {
    pub(super) async fn suspend_environment_inner(
        &self,
        request: v1::SuspendEnvironmentRequest,
    ) -> Result<v1::SuspendEnvironmentResponse, Status> {
        let name = validate_sleep_name(&request.name)?;
        let expected_environment_id = optional_expected_environment_id(&request.environment_id)?;
        let reason = if request.reason.trim().is_empty() {
            "user"
        } else {
            request.reason.trim()
        };
        if !matches!(reason, "user" | "idle") {
            return Err(Status::invalid_argument(format!(
                "unsupported suspend reason: {reason}"
            )));
        }
        self.start_drains()?;
        let _lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        require_expected_environment(&environment, expected_environment_id)?;
        if environment.state != StoredEnvironmentState::Running {
            return Err(Status::failed_precondition(
                "environment must be running to suspend",
            ));
        }
        let artifact_generation =
            artifact_generation_for_boot(&environment, false).map_err(Status::from)?;
        let mut client = self
            .supervisor
            .runner_client_for_artifact(&name, artifact_generation)
            .await
            .map_err(Status::from)?;
        let reply = client
            .suspend_vm(
                environment.id,
                environment.generation,
                Uuid::new_v4(),
                reason,
            )
            .await?;
        let mut shown = self
            .supervisor
            .core()
            .environment_proto(&name)
            .map_err(Status::from)?;
        if let Some(info) = reply.runner.as_ref() {
            runner_report::apply_runner_info(&mut shown, info);
        }
        Ok(v1::SuspendEnvironmentResponse {
            environment: Some(shown),
            already_suspended: reply.already_suspended,
        })
    }

    pub(super) async fn resume_environment_inner(
        &self,
        request: v1::ResumeEnvironmentRequest,
    ) -> Result<v1::ResumeEnvironmentResponse, Status> {
        let name = validate_sleep_name(&request.name)?;
        let expected_environment_id = optional_expected_environment_id(&request.environment_id)?;
        self.start_drains()?;
        let _lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        require_expected_environment(&environment, expected_environment_id)?;
        if environment.state != StoredEnvironmentState::Running {
            let message = if environment.state == StoredEnvironmentState::Stopped {
                format!("environment {name} is stopped; start it with `cw --local start {name}`")
            } else {
                format!(
                    "environment {name} is not running or suspended (state: {})",
                    environment.state.as_str()
                )
            };
            return Err(Status::failed_precondition(message));
        }
        let artifact_generation =
            artifact_generation_for_boot(&environment, false).map_err(Status::from)?;
        let mut client = self
            .supervisor
            .runner_client_for_artifact(&name, artifact_generation)
            .await
            .map_err(Status::from)?;
        let reply = client
            .resume_vm(environment.id, environment.generation)
            .await?;
        let mut shown = self
            .supervisor
            .core()
            .environment_proto(&name)
            .map_err(Status::from)?;
        if let Some(info) = reply.runner.as_ref() {
            runner_report::apply_runner_info(&mut shown, info);
        }
        Ok(v1::ResumeEnvironmentResponse {
            environment: Some(shown),
            already_running: reply.already_running,
            wake_duration_ms: reply.wake_duration_ms,
        })
    }
}

fn validate_sleep_name(raw: &str) -> Result<String, Status> {
    if !crate::supervisor_metadata::valid_environment_name(raw) {
        return Err(Status::invalid_argument("invalid environment name"));
    }
    Ok(raw.to_owned())
}

fn optional_expected_environment_id(raw: &str) -> Result<Option<Uuid>, Status> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let id =
        Uuid::parse_str(trimmed).map_err(|_| Status::invalid_argument("invalid environment_id"))?;
    Ok(Some(id))
}
