//! `GetManagedRuntime`: the public runtime identity of a running VM, from
//! its immutable UUID's retained native binding.

use super::*;

impl SupervisorRpc {
    pub(super) async fn managed_runtime(
        &self,
        request: v1::EnvironmentSelector,
    ) -> Result<v1::ManagedRuntime, Status> {
        let expected = parse_optional_environment_id(&request.environment_id)
            .map_err(Status::from)?
            .ok_or_else(|| {
                Status::invalid_argument("managed runtime requires an environment UUID")
            })?;
        let name = selected_name(request)?;
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
        if self
            .supervisor
            .core()
            .incompatible_runners
            .contains(&expected)
        {
            return Err(Status::from(SupervisorError::RunnerProtocolUnsupported));
        }
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        let generation = managed_runtime_artifact_generation(&environment, expected)?.to_owned();
        let runtime_generation = environment
            .cw_runtime
            .as_ref()
            .filter(|binding| binding.staging_catalog_generation.is_none())
            .map(|binding| binding.active_catalog_generation.clone())
            .filter(|generation| {
                environment.runner.as_ref().is_some_and(|runner| {
                    runner.cw_runtime_catalog_generation.as_ref() == Some(generation)
                })
            })
            .ok_or_else(|| {
                Status::failed_precondition("running VM has no admitted cw runtime catalog")
            })?;
        let engine_root = self.supervisor.config.engine_root();
        let open_generation = runtime_generation.clone();
        let disk = tokio::task::spawn_blocking(move || {
            let engine = PrivateRoot::open(&engine_root)?;
            CwRuntimeStore::create(&engine)?.open_catalog(&open_generation)
        })
        .await
        .map_err(|_| Status::internal("cw runtime admission task failed"))?
        .map_err(|_| Status::failed_precondition("retained cw runtime catalog is unavailable"))?;
        let provenance_json = serde_json::to_vec(
            disk.manifest
                .catalog
                .active()
                .map_err(Status::failed_precondition)?,
        )
        .map_err(|_| Status::internal("cw runtime provenance encoding failed"))?;
        let catalog_json = disk
            .manifest
            .catalog
            .encode()
            .map_err(Status::failed_precondition)?;
        Ok(v1::ManagedRuntime {
            environment_id: expected.to_string(),
            artifact_generation: generation,
            provenance_json,
            catalog_json,
            cw_runtime_catalog_generation: runtime_generation,
        })
    }
}
