//! One durable operation owns source replacement, its generation and restart.
//! This journal contains canonical configuration and metadata, never protected
//! values, launch projections, delegation tokens or upstream diagnostics.

use super::*;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceProfile {
    id: String,
    revision: u64,
    reference: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceSelection {
    project_spec_json: String,
    project_spec_sha256: String,
    profile: Option<SourceProfile>,
    platform_source_authority: Option<PlatformSourceAuthority>,
}

impl SourceSelection {
    fn validate(&self) -> Result<ProjectSpec, SupervisorError> {
        validate_project_intent(
            self.project_spec_json.as_bytes(),
            &self.project_spec_sha256,
            None,
        )
        .map_err(|_| SupervisorError::InvalidRequest)?;
        let project: ProjectSpec = serde_json::from_str(&self.project_spec_json)
            .map_err(|_| SupervisorError::InvalidRequest)?;
        let (id, revision, reference) = self
            .profile
            .as_ref()
            .map(|profile| {
                (
                    profile.id.as_str(),
                    profile.revision,
                    profile.reference.as_str(),
                )
            })
            .unwrap_or(("", 0, ""));
        validate_source_metadata(
            &project,
            id,
            revision,
            reference,
            self.platform_source_authority
                .as_ref()
                .map(PlatformSourceAuthority::proto)
                .as_ref(),
        )?;
        Ok(project)
    }

    fn from_environment(environment: &EnvironmentRecord) -> Result<Self, SupervisorError> {
        let profile = match (&environment.access_profile, &environment.access_binding) {
            (None, None) => None,
            (Some(reference), Some(binding))
                if binding.environment_id == access_environment_id(environment.id)? =>
            {
                Some(SourceProfile {
                    id: binding.profile_id.to_string(),
                    revision: binding.profile_revision,
                    reference: reference.to_string(),
                })
            }
            _ => return Err(SupervisorError::InvalidState),
        };
        let result = Self {
            project_spec_json: String::from_utf8(
                environment
                    .project_spec_json
                    .clone()
                    .ok_or(SupervisorError::InvalidState)?,
            )
            .map_err(|_| SupervisorError::InvalidState)?,
            project_spec_sha256: environment
                .project_spec_sha256
                .clone()
                .ok_or(SupervisorError::InvalidState)?,
            profile,
            platform_source_authority: environment.platform_source_authority.clone(),
        };
        result
            .validate()
            .map_err(|_| SupervisorError::InvalidState)?;
        Ok(result)
    }

    fn from_request(
        request: &v1::UpdateEnvironmentSourcesRequest,
    ) -> Result<Self, SupervisorError> {
        let profile = match (
            request.access_profile_id.is_empty(),
            request.access_profile_revision,
            request.access_profile_reference.is_empty(),
        ) {
            (true, 0, true) => None,
            (false, revision, false) if revision > 0 => Some(SourceProfile {
                id: request.access_profile_id.clone(),
                revision,
                reference: request.access_profile_reference.clone(),
            }),
            _ => return Err(SupervisorError::InvalidRequest),
        };
        let result = Self {
            project_spec_json: String::from_utf8(request.project_spec_json.clone())
                .map_err(|_| SupervisorError::InvalidRequest)?,
            project_spec_sha256: request.project_spec_sha256.clone(),
            profile,
            platform_source_authority: request
                .platform_source_authority
                .as_ref()
                .map(PlatformSourceAuthority::from_proto)
                .transpose()?,
        };
        result.validate()?;
        Ok(result)
    }

    fn binding(
        &self,
        environment_id: Uuid,
    ) -> Result<Option<EnvironmentAccessBinding>, SupervisorError> {
        self.profile
            .as_ref()
            .map(|profile| {
                Ok(EnvironmentAccessBinding {
                    environment_id: access_environment_id(environment_id)?,
                    profile_id: AccessProfileId::parse(&profile.id)
                        .map_err(|_| SupervisorError::InvalidState)?,
                    profile_revision: profile.revision,
                })
            })
            .transpose()
    }

    fn local_binding(
        &self,
        environment_id: Uuid,
    ) -> Result<Option<EnvironmentAccessBinding>, SupervisorError> {
        let project = self.validate()?;
        if let Some(credentials) = project.credentials {
            let reference = StorageReference::profile(&credentials.profile)
                .map_err(|_| SupervisorError::InvalidState)?;
            if exact_reference(reference)? == StoragePlacement::Local {
                return self.binding(environment_id);
            }
        }
        Ok(None)
    }

    fn write_to(&self, environment: &mut EnvironmentRecord) -> Result<(), SupervisorError> {
        self.validate()?;
        environment.project_spec_json = Some(self.project_spec_json.as_bytes().to_vec());
        environment.project_spec_sha256 = Some(self.project_spec_sha256.clone());
        environment.access_binding = self.binding(environment.id)?;
        environment.access_profile = self
            .profile
            .as_ref()
            .map(|profile| {
                profile
                    .reference
                    .parse()
                    .map_err(|_| SupervisorError::InvalidState)
            })
            .transpose()?;
        environment.platform_source_authority = self.platform_source_authority.clone();
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceTransition {
    name: String,
    expected_generation: u64,
    target_generation: u64,
    expected: SourceSelection,
    target: SourceSelection,
    was_running: bool,
    allow_restart: bool,
}

impl SourceTransition {
    fn validate(&self) -> Result<(), SupervisorError> {
        if !valid_environment_name(&self.name)
            || self.expected_generation == 0
            || self.expected_generation.checked_add(1) != Some(self.target_generation)
            || (self.was_running && !self.allow_restart)
        {
            return Err(SupervisorError::InvalidRequest);
        }
        let mut expected = self.expected.validate()?;
        let mut target = self.target.validate()?;
        // Every new/replayed target must be deliverable, even while stopped.
        // Expected metadata may describe an unavailable selection being
        // explicitly cleared; it must not prevent that repair operation.
        platform::requires_platform_authority(&target)?;
        expected.secrets = Default::default();
        expected.credentials = None;
        target.secrets = Default::default();
        target.credentials = None;
        if expected != target {
            return Err(SupervisorError::InvalidRequest);
        }
        Ok(())
    }

    fn new(
        request: &v1::UpdateEnvironmentSourcesRequest,
        environment: &EnvironmentRecord,
    ) -> Result<Self, SupervisorError> {
        let result = Self {
            name: request.name.clone(),
            expected_generation: request.expected_generation,
            target_generation: request
                .expected_generation
                .checked_add(1)
                .ok_or(SupervisorError::InvalidRequest)?,
            expected: SourceSelection::from_environment(environment)?,
            target: SourceSelection::from_request(request)?,
            was_running: environment.state == StoredEnvironmentState::Running,
            allow_restart: request.allow_restart,
        };
        result.validate()?;
        if !matches!(
            environment.state,
            StoredEnvironmentState::Stopped | StoredEnvironmentState::Running
        ) || environment.staging_workspace_generation.is_some()
            || environment.staging_artifact_generation.is_some()
            || environment.generation != result.expected_generation
            || !result.matches_request(request, environment.id)?
        {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
        Ok(result)
    }

    fn matches_request(
        &self,
        request: &v1::UpdateEnvironmentSourcesRequest,
        environment_id: Uuid,
    ) -> Result<bool, SupervisorError> {
        let expected_id = parse_optional_environment_id(&request.expected_environment_id)?
            .ok_or(SupervisorError::InvalidRequest)?;
        let (profile_id, revision) = self
            .expected
            .profile
            .as_ref()
            .map(|profile| (profile.id.as_str(), profile.revision))
            .unwrap_or(("", 0));
        Ok(expected_id == environment_id
            && self.name == request.name
            && self.expected_generation == request.expected_generation
            && self.expected.project_spec_sha256 == request.expected_project_spec_sha256
            && profile_id == request.expected_access_profile_id
            && revision == request.expected_access_profile_revision
            && self.expected.platform_source_authority
                == request
                    .expected_platform_source_authority
                    .as_ref()
                    .map(PlatformSourceAuthority::from_proto)
                    .transpose()?
            && self.target == SourceSelection::from_request(request)?
            && self.allow_restart == request.allow_restart)
    }

    fn validate_running_delivery(
        &self,
        environment: &EnvironmentRecord,
    ) -> Result<(), SupervisorError> {
        if !self.was_running {
            return Ok(());
        }
        self.target.validate()?;
        let mut candidate = environment.clone();
        self.target.write_to(&mut candidate)?;
        // Only material-free installed-build/delivery feasibility here. The
        // current runtime stays untouched when a target path is still gated.
        // Clearing sources and stopped metadata updates remain admissible.
        validate_environment_workload_secret_delivery(&candidate, false)
    }

    fn from_operation(operation: &OperationRecord) -> Result<Self, SupervisorError> {
        if operation.kind != OperationKind::UpdateEnvironmentSources
            || operation.environment_id.is_none()
            || operation.environment_id.is_some_and(|id| id.is_nil())
        {
            return Err(SupervisorError::InvalidState);
        }
        let transition: Self = serde_json::from_value(operation.payload.clone())
            .map_err(|_| SupervisorError::InvalidState)?;
        transition
            .validate()
            .map_err(|_| SupervisorError::InvalidState)?;
        Ok(transition)
    }

    fn require_current(
        &self,
        environment: &EnvironmentRecord,
        operation: &OperationRecord,
    ) -> Result<(), SupervisorError> {
        let committed = operation.checkpoint >= 4;
        let (selection, generation) = if committed {
            (&self.target, self.target_generation)
        } else {
            (&self.expected, self.expected_generation)
        };
        if operation.environment_id != Some(environment.id)
            || environment.name != self.name
            || environment.generation != generation
            || SourceSelection::from_environment(environment)? != *selection
        {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
        Ok(())
    }
}

impl SupervisorRpc {
    pub(in crate::supervisor) async fn admit_source_update(
        &self,
        request: v1::UpdateEnvironmentSourcesRequest,
    ) -> Result<Response<v1::Operation>, Status> {
        if !valid_environment_name(&request.name) || request.expected_generation == 0 {
            return Err(Status::invalid_argument("invalid source update request"));
        }
        let request_id = parse_request_id(&request.request_id).map_err(Status::from)?;
        let environment_id = parse_optional_environment_id(&request.expected_environment_id)
            .map_err(Status::from)?
            .ok_or_else(|| Status::invalid_argument("environment ID is required"))?;
        SourceSelection::from_request(&request).map_err(Status::from)?;
        self.start_drains()?;
        let mut lease = self.supervisor.lease(&request.name).lock_owned().await;
        let existing = self
            .supervisor
            .core()
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let admitted = existing.is_none();
        let operation = if let Some(operation) = existing {
            let recorded = SourceTransition::from_operation(&operation)
                .map_err(|_| Status::aborted("local lifecycle request ID collision"))?;
            if operation.environment_id != Some(environment_id)
                || !recorded
                    .matches_request(&request, environment_id)
                    .map_err(Status::from)?
            {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            require_expected_environment(
                &self
                    .supervisor
                    .environment(&request.name)
                    .map_err(Status::from)?,
                Some(environment_id),
            )?;
            lease = self
                .supervisor
                .drain_under(lease, &request.name)
                .await
                .map_err(Status::from)?;
            let environment = self
                .supervisor
                .environment(&request.name)
                .map_err(Status::from)?;
            require_expected_environment(&environment, Some(environment_id))?;
            let transition = SourceTransition::new(&request, &environment).map_err(Status::from)?;
            transition
                .validate_running_delivery(&environment)
                .map_err(Status::from)?;
            if let Some(binding) = transition
                .target
                .local_binding(environment_id)
                .map_err(Status::from)?
            {
                // Prove the immutable name/ID/revision tuple before the intent
                // becomes replayable. A later lost ACK can then be reconciled
                // by exact binding identity without trusting a caller label.
                let mut metadata = codewire_local_credentials::LocalCredentialClient::connect(
                    &self.supervisor.config.credential_authority_config(),
                )
                .await
                .map_err(|_| Status::unavailable("local credential authority is unavailable"))?;
                let profile = metadata
                    .get_profile_revision(&binding.profile_id, binding.profile_revision)
                    .await
                    .map_err(|status| Status::from(credential_control_error(status)))?;
                let reference = transition
                    .target
                    .profile
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("invalid source profile"))?
                    .reference
                    .parse::<AccessProfileReference>()
                    .map_err(|_| Status::invalid_argument("invalid source profile"))?;
                if profile.profile.id != binding.profile_id
                    || profile.profile.revision != binding.profile_revision
                    || profile.profile.name != *reference.name()
                {
                    return Err(Status::failed_precondition(
                        "local environment access profile does not match",
                    ));
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Status::failed_precondition("host time is unavailable"))?
                    .as_secs();
                for id in profile
                    .profile
                    .entries
                    .values()
                    .collect::<std::collections::BTreeSet<_>>()
                {
                    let credential = metadata
                        .get_credential(id)
                        .await
                        .map_err(|status| Status::from(credential_control_error(status)))?;
                    if credential.metadata.id != *id
                        || credential.metadata.placement != profile.profile.placement
                        || credential.metadata.owner != profile.profile.owner
                        || !source_credential_active(&credential.metadata, now)
                    {
                        return Err(Status::failed_precondition(
                            "local profile credential is unavailable",
                        ));
                    }
                }
            }
            let payload = serde_json::to_value(transition)
                .map_err(|_| Status::invalid_argument("invalid source update request"))?;
            self.supervisor
                .core()
                .store
                .begin_operation(
                    request_id,
                    Some(environment_id),
                    OperationKind::UpdateEnvironmentSources,
                    &payload,
                )
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        if admitted && !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&request.name);
        }
        Ok(Response::new(response))
    }
}

fn source_credential_active(metadata: &codewire_access::CredentialMetadata, now: u64) -> bool {
    metadata.validate().is_ok()
        && metadata.status == codewire_access::CredentialStatus::Active
        && metadata
            .expires_at_unix
            .is_none_or(|deadline| deadline > now)
}

#[tonic::async_trait]
trait BindingAuthority: Send {
    async fn apply(
        &mut self,
        environment_id: &codewire_access::EnvironmentId,
        expected: Option<&EnvironmentAccessBinding>,
        target: Option<(&EnvironmentAccessBinding, &AccessProfileReference)>,
    ) -> Result<(), Status>;
    async fn read(
        &mut self,
        environment_id: &codewire_access::EnvironmentId,
    ) -> Result<Option<EnvironmentAccessBinding>, Status>;
}

#[tonic::async_trait]
impl BindingAuthority for LocalCredentialControlClient {
    async fn apply(
        &mut self,
        environment_id: &codewire_access::EnvironmentId,
        expected: Option<&EnvironmentAccessBinding>,
        target: Option<(&EnvironmentAccessBinding, &AccessProfileReference)>,
    ) -> Result<(), Status> {
        self.apply_environment_access_binding(environment_id, expected, target)
            .await
            .map(|_| ())
    }
    async fn read(
        &mut self,
        environment_id: &codewire_access::EnvironmentId,
    ) -> Result<Option<EnvironmentAccessBinding>, Status> {
        match self.get_environment_access_binding(environment_id).await {
            Ok(record) => Ok(Some(record.binding)),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(status),
        }
    }
}

async fn publish_binding(
    authority: &mut impl BindingAuthority,
    environment_id: &codewire_access::EnvironmentId,
    expected: Option<&EnvironmentAccessBinding>,
    target: Option<(&EnvironmentAccessBinding, &AccessProfileReference)>,
) -> Result<(), SupervisorError> {
    // An unknown ACK is not a failed publication. Resolve only against the two
    // recorded values; a retry never adopts a newer binding as its expected CAS.
    for _ in 0..2 {
        match authority.apply(environment_id, expected, target).await {
            Ok(()) => return Ok(()),
            Err(status) => {
                let ambiguous = matches!(
                    status.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown
                );
                // Even a denied or malformed metadata response cannot prove
                // whether the preceding write committed. Keep this pending.
                let current = authority
                    .read(environment_id)
                    .await
                    .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?;
                if current.as_ref() == target.map(|(binding, _)| binding) {
                    // A preceding worker may already have published target.
                    // If this attempt could not validate its profile/reference,
                    // do not accept the claim or declare that prior publication
                    // failed. Keep the exact journal pending for reconciliation.
                    return if ambiguous {
                        Ok(())
                    } else {
                        Err(SupervisorError::CredentialAuthorityUnavailable)
                    };
                }
                if current.as_ref() != expected {
                    return Err(SupervisorError::EnvironmentAccessUnavailable);
                }
                if !ambiguous {
                    return Err(credential_control_error(status));
                }
            }
        }
    }
    Err(SupervisorError::CredentialAuthorityUnavailable)
}

impl Supervisor {
    pub(in crate::supervisor) async fn execute_source_operation(
        &self,
        operation: &OperationRecord,
    ) -> Result<(), SupervisorError> {
        match self.update_environment_sources(operation).await {
            Ok(completed) => {
                let transition = SourceTransition::from_operation(&completed)?;
                let result = environment_operation_result(&self.environment(&transition.name)?);
                self.core().complete_operation(&completed, &result)?;
                Ok(())
            }
            // This also covers an unknown binding ACK: keep the immutable
            // journal pending until its exact publication can be reconciled.
            Err(
                error @ (SupervisorError::CredentialAuthorityUnavailable
                | SupervisorError::Store(_)),
            ) => Err(error),
            Err(error) => {
                let current = self
                    .core()
                    .store
                    .operation_by_request(operation.request_id)?
                    .ok_or(SupervisorError::InvalidState)?;
                let transition = SourceTransition::from_operation(&current)?;
                if self
                    .environment(&transition.name)
                    .is_ok_and(|environment| Some(environment.id) == current.environment_id)
                {
                    // The cause is closed vocabulary (#2595): the error class,
                    // or the runner's own code for a failed VM start. Read the
                    // runner's code before the stop below retires it.
                    let code = if matches!(error, SupervisorError::EnvironmentAccessUnavailable) {
                        "environment_sources_conflict".to_owned()
                    } else {
                        lifecycle_failure_code(
                            "environment_sources",
                            &error,
                            self.core().recorded_runner_error_code(&transition.name),
                        )
                    };
                    self.core()
                        .log_operation_failure(&current, &transition.name, &error, &code);
                    // If a target launch partially succeeded, prove it stopped
                    // before publishing terminal failure. Never roll back pins.
                    self.ensure_vm_stopped(&transition.name).await?;
                    self.core().fail_operation_with_environment_error(
                        &current,
                        &transition.name,
                        &code,
                    )?;
                } else {
                    self.core().log_operation_failure(
                        &current,
                        &transition.name,
                        &error,
                        "environment_sources_conflict",
                    );
                    self.core()
                        .fail_operation(&current, "environment_sources_conflict")?;
                }
                Ok(())
            }
        }
    }

    async fn update_environment_sources(
        &self,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        let transition = SourceTransition::from_operation(operation)?;
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            transition.require_current(&self.environment(&transition.name)?, &operation)?;
            match effect {
                LifecycleEffect::StopVm => {
                    self.reconcile_active_environment_before_protected_effect(&transition.name)
                        .await?;
                    self.ensure_vm_stopped(&transition.name).await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    operation = self.commit_operation(&operation, |next| {
                        next.environments
                            .get_mut(&transition.name)
                            .ok_or(SupervisorError::InvalidState)?
                            .state = StoredEnvironmentState::Stopped;
                        Ok(())
                    })?;
                }
                LifecycleEffect::ApplySourceAccessBinding => {
                    let expected = transition.expected.local_binding(environment_id)?;
                    let target = transition.target.local_binding(environment_id)?;
                    if expected.is_some() || target.is_some() {
                        let reference = transition
                            .target
                            .profile
                            .as_ref()
                            .map(|profile| {
                                profile
                                    .reference
                                    .parse::<AccessProfileReference>()
                                    .map_err(|_| SupervisorError::InvalidState)
                            })
                            .transpose()?;
                        let mut authority = self.access_control_client().await?;
                        publish_binding(
                            &mut authority,
                            &access_environment_id(environment_id)?,
                            expected.as_ref(),
                            target.as_ref().zip(reference.as_ref()),
                        )
                        .await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordEnvironmentSources => {
                    operation = self.commit_operation(&operation, |next| {
                        let environment = next
                            .environments
                            .get_mut(&transition.name)
                            .ok_or(SupervisorError::InvalidState)?;
                        transition.target.write_to(environment)?;
                        environment.generation = transition.target_generation;
                        environment.state = StoredEnvironmentState::Stopped;
                        Ok(())
                    })?;
                }
                LifecycleEffect::RequireEnvironmentAccess => {
                    if transition.was_running {
                        self.require_environment_access(&transition.name).await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStarting => {
                    operation = self.commit_operation(&operation, |next| {
                        if transition.was_running {
                            let environment = next
                                .environments
                                .get_mut(&transition.name)
                                .ok_or(SupervisorError::InvalidState)?;
                            if !matches!(
                                environment.state,
                                StoredEnvironmentState::Stopped | StoredEnvironmentState::Starting
                            ) {
                                return Err(SupervisorError::InvalidState);
                            }
                            environment.state = StoredEnvironmentState::Starting;
                            if let Some(runner) = environment.runner.as_mut() {
                                runner.error_code = None;
                            }
                        }
                        Ok(())
                    })?;
                }
                LifecycleEffect::EnsureRunner => {
                    if transition.was_running {
                        validate_environment_workload_secret_delivery(
                            &self.environment(&transition.name)?,
                            false,
                        )?;
                        let artifact = artifact_generation_for_boot(
                            &self.environment(&transition.name)?,
                            false,
                        )?
                        .to_owned();
                        self.runner_client_for_artifact(&transition.name, &artifact)
                            .await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    if transition.was_running {
                        self.ensure_vm_started(
                            &transition.name,
                            transition.target_generation,
                            operation.operation_id,
                        )
                        .await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordSourceOutcome => {
                    if transition.was_running {
                        // A same-host supervisor crash can outlive its VM.
                        // Check physical runner liveness again; a checkpoint
                        // after StartVm is not perpetual evidence of Running.
                        self.reconcile(&transition.name).await?;
                        let current = self.environment(&transition.name)?;
                        transition.require_current(&current, &operation)?;
                        if current.state != StoredEnvironmentState::Running
                            || current.runner.is_none()
                        {
                            return Err(SupervisorError::NotRunning);
                        }
                    }
                    operation = self.commit_operation(&operation, |next| {
                        next.environments
                            .get_mut(&transition.name)
                            .ok_or(SupervisorError::InvalidState)?
                            .state = if transition.was_running {
                            StoredEnvironmentState::Running
                        } else {
                            StoredEnvironmentState::Stopped
                        };
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok(operation)
    }
}

#[cfg(test)]
mod tests;
