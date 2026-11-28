//! What a generation's credential broker is ensured with: the bindings it
//! serves and the network policy's answers it is given, decided here, where
//! the policy is held (#4926, #5555).

use super::*;

#[derive(Clone)]
pub(super) struct CredentialBrokerEnsureRequest {
    pub(super) authority: AuthorityRuntimeConfig,
    pub(super) environment_id: EnvironmentId,
    pub(super) environment_generation: u64,
    pub(super) environment_name: String,
    pub(super) runner_socket: PathBuf,
    pub(super) projection: Option<codewire_local_credentials::LocalEnvironmentProjectionBinding>,
    pub(super) platform: Option<codewire_local_credentials::PlatformCredentialBinding>,
    pub(super) local_profile: Option<EnvironmentAccessBinding>,
    pub(super) network_policy_allows_github: bool,
    /// The bound hosts the network policy allows by rule on 443 (#5555).
    pub(super) network_policy_allowed_hosts: std::collections::BTreeSet<String>,
    /// The policy those hosts were decided under, as the supervisor names
    /// it: what the runner labels an intercepted host's `name_not_allowed`
    /// with, and never anything the front door says (#5058).
    pub(super) network_policy_label: v1::NetworkPolicyLabel,
    /// That policy, which answers for the hosts of the bound secrets the
    /// boot recorded (#4003) once its runner gives the record.
    pub(super) network_policy: codewire_egress_policy::CompiledPolicy,
    pub(super) enabled: bool,
}

impl SupervisorCore {
    pub(super) fn credential_broker_ensure_request(
        &self,
        name: &str,
    ) -> Result<CredentialBrokerEnsureRequest, SupervisorError> {
        let environment = self.environment(name)?;
        if environment.state != StoredEnvironmentState::Running
            || environment.generation == 0
            || environment.runner.is_none()
        {
            return Err(SupervisorError::NotRunning);
        }
        self.credential_broker_request_for_environment(environment, environment.generation)
    }

    pub(super) fn credential_broker_request_for_environment(
        &self,
        environment: &EnvironmentRecord,
        generation: u64,
    ) -> Result<CredentialBrokerEnsureRequest, SupervisorError> {
        if generation == 0 {
            return Err(SupervisorError::InvalidState);
        }
        let mut platform =
            sources::platform::broker_binding(environment, &self.config.platform_config_dir)?;
        if let Some(binding) = platform.as_mut() {
            sources::platform::resolve_config_directory(binding)?;
        }
        let projection = sources::local_launch_projection(environment)?;
        let local_profile = if platform
            .as_ref()
            .is_some_and(|binding| binding.selection.profile.is_some())
        {
            None
        } else {
            environment.access_binding.clone()
        };
        let selected = self
            .network_policies
            .environment_policy(environment.id)
            .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?
            .selected;
        let policy = selected.compile();
        Ok(CredentialBrokerEnsureRequest {
            authority: self.config.credential_authority_config(),
            environment_id: access_environment_id(environment.id)?,
            environment_generation: generation,
            environment_name: environment.name.clone(),
            runner_socket: self.config.runner_socket(environment.id),
            enabled: environment.access_binding.is_some()
                || projection.is_some()
                || platform.is_some(),
            projection,
            platform,
            local_profile,
            // The credential broker never sees the network policy, so its
            // answers are decided here, from the same selection this
            // environment's egress broker enforces (#4926, #5555).
            network_policy_allows_github: policy.allows_managed_github(),
            network_policy_allowed_hosts: broker_ensure::allowed_bound_hosts(&policy),
            network_policy_label: crate::runner_service::policy_label(&selected),
            network_policy: policy,
        })
    }
}
