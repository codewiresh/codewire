//! The StartEnvironment RPC: journal a Start of one environment, stopped or
//! running, and drain it.

use super::*;

impl SupervisorRpc {
    pub(super) async fn begin_start(
        &self,
        request: v1::EnvironmentSelector,
    ) -> Result<Response<v1::Operation>, Status> {
        let start_with_uncleared_disk = request.start_with_uncleared_disk;
        let (name, request_id, expected_environment_id) = mutation_selection(request)?;
        self.start_drains()?;
        let lease = self
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
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;
        let existing = self
            .supervisor
            .core()
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            if operation.kind != OperationKind::Start
                || operation.environment_id != Some(environment.id)
                || operation
                    .payload
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    != Some(name.as_str())
            {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            let generation = if environment.state == StoredEnvironmentState::Running {
                environment.generation
            } else {
                environment
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| Status::internal("local generation overflow"))?
            };
            let mut payload = serde_json::json!({"name": name, "generation": generation});
            // Journaled only when set, so every other Start's payload is
            // unchanged (#6277).
            if start_with_uncleared_disk && let Some(fields) = payload.as_object_mut() {
                fields.insert(
                    checkpoints::START_WITH_UNCLEARED_DISK.to_owned(),
                    true.into(),
                );
            }
            self.supervisor
                .core()
                .store
                .begin_operation(
                    request_id,
                    Some(environment.id),
                    OperationKind::Start,
                    &payload,
                )
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&name);
        }
        Ok(Response::new(response))
    }
}
