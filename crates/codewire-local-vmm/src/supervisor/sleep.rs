//! Supervisor RPCs for suspending, resuming, and hibernating local Linux VMs
//! (#5529, protocol 30/31, `docs/dev/LOCAL-VM-SLEEP.md`).

use super::*;

struct HibernatingGuard<'a> {
    supervisor: &'a Supervisor,
    id: Uuid,
}

impl Drop for HibernatingGuard<'_> {
    fn drop(&mut self) {
        self.supervisor
            .hibernating
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl Supervisor {
    pub(super) fn hibernating_info(&self, id: Uuid) -> Option<(i64, String)> {
        self.hibernating
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    fn begin_hibernating(&self, id: Uuid, reason: &str) -> HibernatingGuard<'_> {
        self.hibernating
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, (hibernate::now_unix_ms(), reason.to_owned()));
        HibernatingGuard {
            supervisor: self,
            id,
        }
    }

    /// Arms wake-stub loopback listeners on startup for any hibernated VM that
    /// has published host ports.
    pub(super) async fn arm_hibernated_port_wakers_for_startup(self: &Arc<Self>) {
        let engine_root = self.config.engine_root();
        let targets: Vec<(Uuid, String, Vec<HostPortBinding>)> = {
            let core = self.core();
            core.state
                .environments
                .values()
                .filter(|env| {
                    env.state == StoredEnvironmentState::Stopped
                        && !env.host_ports.is_empty()
                        && hibernate::is_hibernated(&engine_root, env.id)
                })
                .map(|env| (env.id, env.name.clone(), env.host_ports.clone()))
                .collect()
        };
        for (id, name, host_ports) in targets {
            self.hibernate_port_wakers
                .arm(Arc::clone(self), id, name, &host_ports)
                .await;
        }
    }

    /// Wakes a hibernated VM while the caller already holds `quiet_lease(name)`,
    /// journaling a standard `Start` operation so restore, fallback, broker, and
    /// crash recovery all go through one path.
    pub(super) async fn wake_hibernated_under_lease(
        &self,
        name: &str,
    ) -> Result<v1::Environment, SupervisorError> {
        let environment = self.environment(name)?;
        reject_environment_workload_secrets(&environment)?;
        let generation = environment
            .generation
            .checked_add(1)
            .ok_or(SupervisorError::InvalidState)?;
        let payload = serde_json::json!({
            "name": name,
            "generation": generation,
        });
        let operation = self.core().store.begin_operation(
            Uuid::new_v4(),
            Some(environment.id),
            OperationKind::Start,
            &payload,
        )?;
        let (env_proto, completed) = match self.start(name, &operation).await {
            Ok(result) => result,
            Err(error) => {
                let error_code = lifecycle_failure_code(
                    "start",
                    &error,
                    self.core().recorded_runner_error_code(name),
                );
                self.core()
                    .log_operation_failure(&operation, name, &error, &error_code);
                self.core()
                    .fail_replayed_operation(&operation, name, &error_code)?;
                return Err(error);
            }
        };
        let result = self
            .core()
            .state
            .environments
            .get(name)
            .map(environment_operation_result)
            .ok_or(SupervisorError::InvalidState)?;
        self.core().complete_operation(&completed, &result)?;
        Ok(env_proto)
    }
}

impl SupervisorRpc {
    pub(super) async fn suspend_environment_inner(
        &self,
        request: v1::SuspendEnvironmentRequest,
    ) -> Result<v1::SuspendEnvironmentResponse, Status> {
        let name = validate_sleep_name(&request.name)?;
        let expected_environment_id = optional_expected_environment_id(&request.environment_id)?;
        let reason = normalize_sleep_reason(&request.reason, "suspend")?;
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
        if environment.state == StoredEnvironmentState::Stopped
            && hibernate::is_hibernated(&self.supervisor.config.engine_root(), environment.id)
        {
            return Err(Status::failed_precondition(format!(
                "environment {name} is hibernated and cannot be suspended"
            )));
        }
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
        hibernate::apply_to_environment(&self.supervisor.config.engine_root(), &mut shown);
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
        let engine_root = self.supervisor.config.engine_root();
        if environment.state == StoredEnvironmentState::Stopped
            && hibernate::has_pending_hibernate(&engine_root, environment.id)
        {
            let started = std::time::Instant::now();
            self.supervisor
                .wake_hibernated_under_lease(&name)
                .await
                .map_err(Status::from)?;
            let wake_duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let shown = self
                .supervisor
                .core()
                .environment_proto(&name)
                .map_err(Status::from)?;
            let shown = runner_report::with_runner_report(&self.supervisor, shown).await;
            return Ok(v1::ResumeEnvironmentResponse {
                environment: Some(shown),
                already_running: false,
                wake_duration_ms,
            });
        }
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
        hibernate::apply_to_environment(&engine_root, &mut shown);
        Ok(v1::ResumeEnvironmentResponse {
            environment: Some(shown),
            already_running: reply.already_running,
            wake_duration_ms: reply.wake_duration_ms,
        })
    }

    pub(super) async fn hibernate_environment_inner(
        &self,
        request: v1::HibernateEnvironmentRequest,
    ) -> Result<v1::HibernateEnvironmentResponse, Status> {
        let name = validate_sleep_name(&request.name)?;
        let expected_environment_id = optional_expected_environment_id(&request.environment_id)?;
        let reason = normalize_sleep_reason(&request.reason, "hibernate")?;
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
        let engine_root = self.supervisor.config.engine_root();
        if environment.state == StoredEnvironmentState::Stopped {
            if hibernate::is_hibernated(&engine_root, environment.id) {
                let mut shown = self
                    .supervisor
                    .core()
                    .environment_proto(&name)
                    .map_err(Status::from)?;
                hibernate::apply_to_environment(&engine_root, &mut shown);
                return Ok(v1::HibernateEnvironmentResponse {
                    environment: Some(shown),
                    already_hibernated: true,
                });
            }
            return Err(Status::failed_precondition(
                "environment must be running or suspended to hibernate",
            ));
        }
        if environment.state != StoredEnvironmentState::Running {
            return Err(Status::failed_precondition(format!(
                "environment {name} is {} and cannot be hibernated",
                environment.state.as_str()
            )));
        }
        if environment.staging_workspace_generation.is_some()
            || environment.staging_artifact_generation.is_some()
            || environment
                .cw_runtime
                .as_ref()
                .is_some_and(|binding| binding.staging_catalog_generation.is_some())
        {
            return Err(Status::failed_precondition(format!(
                "{name} has an unfinished workspace or runtime change; restart it first (`cw restart {name}`)"
            )));
        }
        let artifact_generation = artifact_generation_for_boot(&environment, false)
            .map_err(Status::from)?
            .to_owned();
        let engine = PrivateRoot::open(&engine_root)
            .map_err(|error| Status::from(SupervisorError::from(error)))?;
        RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)
            .map_err(Status::from)?
            .open_generation(&artifact_generation)
            .await
            .map_err(artifact_store_error)
            .map_err(Status::from)?
            .require_guest_checkpoint_abi()
            .map_err(|_| {
                Status::failed_precondition(format!(
                    "{name} runs a guest without VM sleep support; restart it once (`cw restart {name}`) to enable hibernate"
                ))
            })?;
        let space_root = engine_root.clone();
        let memory_mib = environment.memory_mib;
        tokio::task::spawn_blocking(move || {
            hibernate::require_hibernate_space(&space_root, memory_mib)
        })
        .await
        .map_err(|_| Status::internal("hibernate disk space check failed"))??;

        let _hibernating_guard = self.supervisor.begin_hibernating(environment.id, reason);
        let operation_id = Uuid::new_v4();
        let mut client = self
            .supervisor
            .runner_client_for_artifact(&name, &artifact_generation)
            .await
            .map_err(Status::from)?;
        let reply = client
            .hibernate_vm(environment.id, environment.generation, operation_id)
            .await?;
        let boot = reply
            .boot
            .as_ref()
            .ok_or_else(|| Status::internal("runner returned no boot bindings for hibernate"))?;
        let opt = |value: &str| (!value.is_empty()).then(|| value.to_owned());
        let record = hibernate::LocalHibernateRecord {
            schema_version: 1,
            restore_generation: environment.generation,
            operation_id,
            environment_id: environment.id,
            vsock_cid: reply.vsock_cid,
            vmm_sha256: reply.vmm_sha256,
            artifact_generation,
            root_generation: reply.root_generation,
            config_sha256: reply.config_sha256,
            state_sha256: reply.state_sha256,
            memory_bytes: reply.memory_bytes,
            setup_disk_bytes: (reply.setup_disk_bytes != 0).then_some(reply.setup_disk_bytes),
            vcpus: environment.vcpus,
            memory_mib: environment.memory_mib,
            disk_bytes: environment.disk_bytes,
            docker_disk_bytes: environment.docker_disk_bytes,
            skill_snapshot_sha256: opt(&boot.skill_snapshot_sha256),
            environment_projection_sha256: opt(&boot.environment_projection_sha256),
            managed_credential_clients: boot.managed_credential_clients.clone(),
            docker: boot.docker,
            cw_runtime_catalog_generation: opt(&boot.cw_runtime_catalog_generation),
            daemon_vsock_port: boot.daemon_vsock_port,
            intercept: boot.intercept,
            host_cpu: checkpoints::local::host_identity().cpu,
            hibernated_at_unix_ms: hibernate::now_unix_ms(),
            hibernate_reason: reason.to_owned(),
        };
        let write_root = engine_root.clone();
        let write_record = record.clone();
        tokio::task::spawn_blocking(move || hibernate::write_record(&write_root, &write_record))
            .await
            .map_err(|_| Status::internal("hibernate metadata task failed"))?
            .map_err(|error| {
                Status::internal(format!("failed to persist hibernate metadata: {error}"))
            })?;

        // Flip durable state to Stopped immediately after persisting the
        // hibernate record so concurrent `cw ls` / `cw info` readers observe
        // `hibernated` instead of a transient `running` state while the
        // broker and runner retire.
        self.supervisor
            .update_environment(&name, |env| {
                env.state = StoredEnvironmentState::Stopped;
                Ok(())
            })
            .map_err(Status::from)?;

        // Stop any broker and retire the runner immediately so the host
        // reclaims all VMM, sidecar, and runner memory.
        let _ = self
            .supervisor
            .stop_environment_broker_if_present(&environment)
            .await;
        self.supervisor
            .retire_existing_runner(&name)
            .await
            .map_err(Status::from)?;
        if !environment.host_ports.is_empty() {
            self.supervisor
                .hibernate_port_wakers
                .arm(
                    Arc::clone(&self.supervisor),
                    environment.id,
                    name.clone(),
                    &environment.host_ports,
                )
                .await;
        }
        let mut shown = self
            .supervisor
            .core()
            .environment_proto(&name)
            .map_err(Status::from)?;
        hibernate::apply_to_environment(&engine_root, &mut shown);
        Ok(v1::HibernateEnvironmentResponse {
            environment: Some(shown),
            already_hibernated: false,
        })
    }
}

fn validate_sleep_name(raw: &str) -> Result<String, Status> {
    if !crate::supervisor_metadata::valid_environment_name(raw) {
        return Err(Status::invalid_argument("invalid environment name"));
    }
    Ok(raw.to_owned())
}

fn normalize_sleep_reason<'a>(raw: &'a str, verb: &str) -> Result<&'a str, Status> {
    match raw.trim() {
        "" | "user" => Ok("user"),
        "idle" => Ok("idle"),
        other => Err(Status::invalid_argument(format!(
            "unsupported {verb} reason: {other}"
        ))),
    }
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
