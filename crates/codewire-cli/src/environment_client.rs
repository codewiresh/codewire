use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use codewire_client::{self as rpc, ClientConfig, ClientError, CodewireClient, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::CLI_VERSION;
use crate::config::ResolvedPlatformConfig;
use crate::organization_client::preset_from_proto;
use crate::presentation::*;

/// Typed EnvironmentService facade preserving the CLI's established
/// presentation shapes over the shared Connect client.
///
/// The CLI keeps its existing presentation DTOs until their owning commands
/// are migrated. This facade is the only place that translates those DTOs to
/// and from the shared generated Connect client.
#[derive(Clone)]
pub struct EnvironmentClient {
    inner: CodewireClient,
}

impl EnvironmentClient {
    #[cfg(test)]
    pub(crate) fn for_test(inner: CodewireClient) -> Self {
        Self { inner }
    }

    pub fn new(config: &ResolvedPlatformConfig) -> anyhow::Result<Self> {
        Ok(Self {
            inner: connect_client(config)?,
        })
    }

    pub async fn list_environments(
        &self,
        org_id: &str,
        include_destroyed: bool,
    ) -> anyhow::Result<Vec<Environment>> {
        let response = self
            .inner
            .list_environments(rpc::ListEnvironmentsRequest {
                org_id: org_id.to_string(),
                include_destroyed,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .environments
            .into_iter()
            .map(environment_from_proto)
            .collect()
    }

    pub async fn create_environment(
        &self,
        org_id: &str,
        request: &CreateEnvironmentRequest,
    ) -> anyhow::Result<Environment> {
        let response = self
            .inner
            .create_environment(proto_create_environment_request(org_id, request))
            .await
            .map_err(display_client_error)?;
        let environment = response
            .environment
            .into_option()
            .map(environment_from_proto)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("CreateEnvironment returned no environment"))?;
        validate_created_environment(&environment, org_id, request)?;
        Ok(environment)
    }

    /// One complete selection CAS. Never refetch or retry a conflict: the
    /// caller must present a new preview for any changed authority or revision.
    pub async fn update_environment_sources(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &UpdateEnvironmentSourcesRequest,
    ) -> anyhow::Result<EnvironmentSourcesUpdate> {
        anyhow::ensure!(
            request.expected_operation_generation > 0,
            "environment operation generation is missing"
        );
        validate_source_selection(&request.expected, true)?;
        validate_source_selection(&request.replacement, true)?;
        let response = self
            .inner
            .update_environment_sources(rpc::UpdateEnvironmentSourcesRequest {
                org_id: org_id.to_owned(),
                environment_id: environment_id.to_owned(),
                expected_operation_generation: request.expected_operation_generation,
                expected: Some(source_selection_to_proto(&request.expected)).into(),
                replacement: Some(source_selection_to_proto(&request.replacement)).into(),
                allow_restart: request.allow_restart,
                confirm_personal_credentials: request.confirm_personal_credentials,
                confirm_personal_secrets: request.confirm_personal_secrets,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        anyhow::ensure!(
            response.environment_id == environment_id
                && response.operation_generation == request.expected_operation_generation,
            "source update returned a different environment operation"
        );
        let selection = response
            .selection
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("source update omitted its complete selection"))
            .and_then(source_selection_from_proto)?;
        anyhow::ensure!(
            selection == request.replacement,
            "source update returned a different selection"
        );
        let outcome = match response.outcome.as_known() {
            Some(rpc::EnvironmentSourcesUpdateOutcome::Unchanged) => {
                EnvironmentSourcesUpdateOutcome::Unchanged
            }
            Some(rpc::EnvironmentSourcesUpdateOutcome::Stored) => {
                EnvironmentSourcesUpdateOutcome::Stored
            }
            Some(rpc::EnvironmentSourcesUpdateOutcome::RestartRequired) => {
                EnvironmentSourcesUpdateOutcome::RestartRequired
            }
            _ => anyhow::bail!("source update returned an unsupported outcome"),
        };
        Ok(EnvironmentSourcesUpdate {
            environment_id: response.environment_id,
            operation_generation: response.operation_generation,
            selection,
            outcome,
        })
    }

    /// Personal platform metadata only; no provider values or material APIs.
    pub async fn resolve_credential_profile(
        &self,
        selector: &str,
    ) -> anyhow::Result<rpc::AccessProfile> {
        let reference = codewire_project::StorageReference::profile(selector)?;
        anyhow::ensure!(
            reference.placement != Some(codewire_project::StoragePlacement::Local),
            "platform environments cannot select local credential profiles"
        );
        let selector = if let Some(id) = reference.selector.strip_prefix("id:") {
            canonical_selection_id(id)?;
            rpc::get_access_profile_request::Selector::AccessProfileId(id.to_owned())
        } else {
            let name = reference
                .selector
                .strip_prefix("user/")
                .unwrap_or(reference.selector);
            anyhow::ensure!(
                !name.contains('/'),
                "organization credential profile resolution is not supported by the platform metadata API yet"
            );
            rpc::get_access_profile_request::Selector::Name(name.to_owned())
        };
        let expected_id = match &selector {
            rpc::get_access_profile_request::Selector::AccessProfileId(id) => Some(id.clone()),
            _ => None,
        };
        let expected_name = match &selector {
            rpc::get_access_profile_request::Selector::Name(name) => Some(name.clone()),
            _ => None,
        };
        let profile = self
            .inner
            .get_access_profile(rpc::GetAccessProfileRequest {
                selector: Some(selector),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?
            .access_profile
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("platform omitted credential profile metadata"))?;
        canonical_selection_id(&profile.id)?;
        anyhow::ensure!(
            profile.revision > 0
                && expected_id.as_ref().is_none_or(|id| id == &profile.id)
                && expected_name
                    .as_ref()
                    .is_none_or(|name| name.eq_ignore_ascii_case(&profile.name)),
            "platform returned a different profile or invalid revision"
        );
        Ok(profile)
    }

    /// Whether this client authenticates with an organization API key, which
    /// has no personal credential profiles.
    pub async fn uses_organization_api_key(&self) -> anyhow::Result<bool> {
        let token = self
            .inner
            .bearer_token()
            .await
            .map_err(display_client_error)?;
        Ok(token.expose_secret().starts_with("cw_"))
    }

    /// The user's default credential profile, from a complete listing, or
    /// none when they have no profiles. A failed listing is an error, never
    /// "no default".
    pub async fn default_credential_profile(&self) -> anyhow::Result<Option<rpc::AccessProfile>> {
        let mut default = None;
        let mut page_token = String::new();
        let mut cursors = std::collections::BTreeSet::new();
        loop {
            let page = self
                .inner
                .list_access_profiles(rpc::ListAccessProfilesRequest {
                    page_size: 100,
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(display_client_error)?;
            for profile in page.access_profiles.into_iter().filter(|p| p.is_default) {
                anyhow::ensure!(
                    default.is_none(),
                    "platform returned more than one default credential profile"
                );
                canonical_selection_id(&profile.id)?;
                default = Some(profile);
            }
            if page.next_page_token.is_empty() {
                return Ok(default);
            }
            anyhow::ensure!(
                cursors.insert(page.next_page_token.clone()),
                "platform returned a repeated profile cursor"
            );
            page_token = page.next_page_token;
        }
    }

    pub async fn prepare_environment_create(
        &self,
        org_id: &str,
        request: &PrepareEnvironmentRequest,
    ) -> anyhow::Result<PrepareEnvironmentResponse> {
        let events = self
            .inner
            .watch_environment_create(rpc::WatchEnvironmentCreateRequest {
                org_id: org_id.to_string(),
                draft: Some(proto_create_environment_request(org_id, &request.draft)).into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let complete = events
            .into_iter()
            .filter_map(|event| event.event)
            .find_map(|event| match event {
                rpc::watch_environment_create_response::Event::Complete(complete) => {
                    Some(*complete)
                }
                rpc::watch_environment_create_response::Event::Progress(_) => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("WatchEnvironmentCreate ended without a complete event")
            })?;
        legacy_prepare_complete(complete)
    }

    pub async fn get_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Environment> {
        Ok(self
            .get_environment_with_poll_interval(org_id, environment_id)
            .await?
            .0)
    }

    pub async fn get_environment_with_poll_interval(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<(Environment, Option<Duration>)> {
        let response = self
            .inner
            .get_environment(rpc::GetEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let poll_interval = response
            .poll_interval
            .into_option()
            .and_then(proto_duration_to_std);
        let environment = response
            .environment
            .into_option()
            .map(environment_from_proto)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("GetEnvironment returned no environment"))?;
        Ok((environment, poll_interval))
    }

    pub async fn resize_environment(
        &self,
        org_id: &str,
        environment_id: &str,
        desired: &EnvironmentResizeResources,
        request_id: &str,
        force: bool,
        allow_restart: bool,
    ) -> anyhow::Result<(EnvironmentResizeResult, Option<Duration>)> {
        let response = self
            .inner
            .resize_environment(rpc::ResizeEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                cpu_millicores: desired.cpu_millicores,
                memory_mb: desired.memory_mb,
                disk_gb: desired.disk_gb,
                request_id: request_id.to_string(),
                force,
                disruption_policy: if allow_restart {
                    rpc::EnvironmentResizeDisruptionPolicy::AllowRestart
                } else {
                    rpc::EnvironmentResizeDisruptionPolicy::LiveOnly
                }
                .into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        legacy_environment_resize_response(
            response.operation.into_option(),
            response.environment.into_option(),
            response.poll_interval.into_option(),
        )
    }

    pub async fn plan_environment_resize(
        &self,
        org_id: &str,
        environment_id: &str,
        desired: &EnvironmentResizeResources,
    ) -> anyhow::Result<EnvironmentResizePlan> {
        let response = self
            .inner
            .plan_environment_resize(rpc::PlanEnvironmentResizeRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                cpu_millicores: desired.cpu_millicores,
                memory_mb: desired.memory_mb,
                disk_gb: desired.disk_gb,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .plan
            .into_option()
            .map(legacy_environment_resize_plan)
            .ok_or_else(|| anyhow::anyhow!("PlanEnvironmentResize returned no plan"))
    }

    pub async fn get_environment_resize_operation(
        &self,
        org_id: &str,
        environment_id: &str,
        operation_id: &str,
    ) -> anyhow::Result<(EnvironmentResizeResult, Option<Duration>)> {
        let response = self
            .inner
            .get_environment_resize_operation(rpc::GetEnvironmentResizeOperationRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                operation_id: operation_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        legacy_environment_resize_response(
            response.operation.into_option(),
            response.environment.into_option(),
            response.poll_interval.into_option(),
        )
    }

    pub async fn get_environment_trust_report(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<EnvironmentTrustReport> {
        let response = self
            .inner
            .get_environment_trust_report(rpc::GetEnvironmentTrustReportRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .trust_report
            .into_option()
            .map(legacy_environment_trust_report)
            .ok_or_else(|| anyhow::anyhow!("GetEnvironmentTrustReport returned no trust report"))
    }

    /// The environment's saved project spec and the sorted names of the
    /// declared environment values the platform withheld from it. A response
    /// that carries any environment value is refused, so no value can reach
    /// an exported file.
    pub async fn get_environment_project_spec(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<(codewire_project::ProjectSpec, Vec<String>)> {
        let response = self
            .inner
            .get_environment_project_spec(rpc::GetEnvironmentProjectSpecRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let spec = response
            .project_spec
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("GetEnvironmentProjectSpec returned no project spec"))?;
        let spec = codewire_project_proto::from_proto(spec).map_err(|error| {
            anyhow::anyhow!("GetEnvironmentProjectSpec returned an invalid project spec: {error}")
        })?;
        anyhow::ensure!(
            spec.environment.is_empty(),
            "GetEnvironmentProjectSpec returned environment values; refusing to export them"
        );
        Ok((spec, response.withheld_environment_keys))
    }

    /// The SSH host key the platform recorded for the environment's current
    /// generation, or `None` when none is recorded (NOT_FOUND). Every other
    /// failure is an error, so the managed OpenSSH block fails closed instead
    /// of trusting any key.
    pub async fn get_environment_host_key(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Option<crate::commands::RecordedHostKey>> {
        let response = match self
            .inner
            .get_environment_host_key(rpc::GetEnvironmentHostKeyRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
        {
            Ok(response) => response,
            Err(error) if error.code() == ErrorCode::NotFound => return Ok(None),
            Err(error) => return Err(display_client_error(error)),
        };
        let generation = u64::try_from(response.generation)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or_else(|| {
                anyhow::anyhow!("GetEnvironmentHostKey returned an invalid generation")
            })?;
        Ok(Some(crate::commands::RecordedHostKey {
            generation,
            public_key_openssh: response.public_key_openssh,
        }))
    }

    pub async fn get_environment_daemon_status(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<EnvironmentDaemonStatus> {
        let response = self
            .inner
            .get_environment_daemon_status(rpc::GetEnvironmentDaemonStatusRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .status
            .into_option()
            .map(legacy_environment_daemon_status)
            .ok_or_else(|| anyhow::anyhow!("GetEnvironmentDaemonStatus returned no status"))
    }

    pub async fn get_environment_daemon_logs(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.inner
            .stream_environment_daemon_logs(
                rpc::StreamEnvironmentDaemonLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    ..Default::default()
                },
                |message| {
                    data.extend_from_slice(&message.data);
                    true
                },
            )
            .await
            .map_err(display_client_error)?;
        Ok(data)
    }

    pub async fn repair_environment_daemon(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<EnvironmentDaemonRepair> {
        let response = self
            .inner
            .repair_environment_daemon(rpc::RepairEnvironmentDaemonRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let status = response
            .status
            .into_option()
            .map(legacy_environment_daemon_status)
            .ok_or_else(|| anyhow::anyhow!("RepairEnvironmentDaemon returned no status"))?;
        Ok(EnvironmentDaemonRepair {
            status,
            replaced_pod_name: response.replaced_pod_name,
        })
    }

    pub async fn stop_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .stop_environment(rpc::StopEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn start_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .start_environment(rpc::StartEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn delete_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .delete_environment(rpc::DeleteEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn protect_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .protect_environment(rpc::ProtectEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn unprotect_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .unprotect_environment(rpc::UnprotectEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn cancel_environment_deletion(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .cancel_environment_deletion(rpc::CancelEnvironmentDeletionRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn extend_environment_ttl(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &ExtendTtlRequest,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .extend_environment_ttl(rpc::ExtendEnvironmentTtlRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                additional_seconds: request.additional_seconds,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn list_environment_access(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<EnvironmentAccessGrant>> {
        let response = self
            .inner
            .list_environment_access(rpc::ListEnvironmentAccessRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(response
            .access_grants
            .into_iter()
            .map(legacy_environment_access_grant)
            .collect())
    }

    pub async fn grant_environment_access(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &GrantEnvironmentAccessRequest,
    ) -> anyhow::Result<EnvironmentAccessGrant> {
        let permission = match request.permission.as_str() {
            "viewer" => rpc::AccessPermission::Viewer,
            "operator" => rpc::AccessPermission::Operator,
            "owner" => rpc::AccessPermission::Owner,
            value => anyhow::bail!("invalid environment access permission {value:?}"),
        };
        let response = self
            .inner
            .grant_environment_access(rpc::GrantEnvironmentAccessRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                user_id: request.user_id.clone(),
                permission: permission.into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .access_grant
            .into_option()
            .map(legacy_environment_access_grant)
            .ok_or_else(|| anyhow::anyhow!("GrantEnvironmentAccess returned no access grant"))
    }

    pub async fn revoke_environment_access(
        &self,
        org_id: &str,
        environment_id: &str,
        user_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .revoke_environment_access(rpc::RevokeEnvironmentAccessRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                user_id: user_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn create_environment_port(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &CreateEnvironmentPortRequest,
    ) -> anyhow::Result<EnvironmentPort> {
        let access = match request.access.as_str() {
            "" => rpc::PortAccess::Unspecified,
            "public" => rpc::PortAccess::Public,
            "org_members" => rpc::PortAccess::OrgMembers,
            "creator" => rpc::PortAccess::Creator,
            value => anyhow::bail!("invalid environment port access {value:?}"),
        };
        let response = self
            .inner
            .create_port(rpc::CreatePortRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                port: request.port,
                label: request.label.clone(),
                access: access.into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .port
            .into_option()
            .map(legacy_environment_port)
            .ok_or_else(|| anyhow::anyhow!("CreatePort returned no port"))
    }

    pub async fn list_environment_ports(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<EnvironmentPort>> {
        let response = self
            .inner
            .list_ports(rpc::ListPortsRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(response
            .ports
            .into_iter()
            .map(legacy_environment_port)
            .collect())
    }

    pub async fn delete_environment_port(
        &self,
        org_id: &str,
        environment_id: &str,
        port_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .delete_port(rpc::DeletePortRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                port_id: port_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn get_environment_logs(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<EnvironmentLog>> {
        let mut logs = Vec::new();
        let mut conversion_error = None;
        self.inner
            .stream_logs(
                rpc::StreamLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    follow: false,
                    ..Default::default()
                },
                |message| match legacy_stream_log(message) {
                    Ok(Some(log)) => {
                        logs.push(log);
                        true
                    }
                    Ok(None) => true,
                    Err(error) => {
                        conversion_error = Some(error);
                        false
                    }
                },
            )
            .await
            .map_err(display_client_error)?;
        if let Some(error) = conversion_error {
            return Err(error);
        }
        Ok(logs)
    }

    /// Opens one following `StreamLogs` connection that resumes strictly
    /// after `after_log_id` (the server's composite cursor). Heartbeats are
    /// surfaced so the caller can detect a silent connection; returning `false`
    /// from `on_event` closes the stream.
    pub async fn follow_environment_log_stream<F>(
        &self,
        org_id: &str,
        environment_id: &str,
        after_log_id: Option<&str>,
        mut on_event: F,
    ) -> Result<(), EnvironmentLogStreamFailure>
    where
        F: FnMut(EnvironmentLogStreamEvent) -> bool,
    {
        let mut conversion_error = None;
        let result = self
            .inner
            .stream_logs(
                rpc::StreamLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    follow: true,
                    after_log_id: after_log_id.unwrap_or_default().to_string(),
                    ..Default::default()
                },
                |message| match message.event {
                    Some(rpc::stream_logs_response::Event::Log(log)) => {
                        match legacy_environment_log(*log) {
                            Ok(log) => on_event(EnvironmentLogStreamEvent::Log(log)),
                            Err(error) => {
                                conversion_error = Some(error);
                                false
                            }
                        }
                    }
                    Some(rpc::stream_logs_response::Event::Heartbeat(_)) => {
                        on_event(EnvironmentLogStreamEvent::Heartbeat)
                    }
                    None => true,
                },
            )
            .await;
        if let Some(error) = conversion_error {
            // The same row would fail again after a reconnect.
            return Err(EnvironmentLogStreamFailure {
                error,
                recovery: LogStreamRecovery::Fatal,
            });
        }
        result.map_err(|error| EnvironmentLogStreamFailure {
            recovery: log_stream_recovery(error.code()),
            error: display_client_error(error),
        })
    }

    pub async fn upload_environment_file(
        &self,
        org_id: &str,
        environment_id: &str,
        remote_path: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut requests = vec![rpc::UploadFileRequest {
            payload: Some(rpc::upload_file_request::Payload::Header(Box::new(
                rpc::UploadFileHeader {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    path: remote_path.to_string(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }];
        if !data.is_empty() {
            requests.push(rpc::UploadFileRequest {
                payload: Some(rpc::upload_file_request::Payload::Chunk(data)),
                ..Default::default()
            });
        }
        self.inner
            .upload_file(requests)
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn download_environment_file(
        &self,
        org_id: &str,
        environment_id: &str,
        remote_path: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let responses = self
            .inner
            .download_file(rpc::DownloadFileRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                path: remote_path.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(responses
            .into_iter()
            .filter_map(|response| match response.payload {
                Some(rpc::download_file_response::Payload::Chunk(chunk)) => Some(chunk),
                Some(rpc::download_file_response::Payload::Info(_)) | None => None,
            })
            .flatten()
            .collect())
    }
}

fn validate_created_environment(
    environment: &Environment,
    org_id: &str,
    request: &CreateEnvironmentRequest,
) -> anyhow::Result<()> {
    let expected = EnvironmentSourceSelection {
        secrets: request.project_spec.secrets.clone(),
        credentials: request.project_spec.credentials.clone(),
        profile_revision: request.expected_profile_revision,
    };
    validate_source_selection(&expected, true)?;
    canonical_selection_id(&environment.id)?;
    anyhow::ensure!(
        environment.org_id == org_id && environment.source_selection.as_ref() == Some(&expected),
        "environment creation returned a different organization or source selection"
    );
    Ok(())
}

pub(crate) fn connect_client(config: &ResolvedPlatformConfig) -> anyhow::Result<CodewireClient> {
    let client_config = ClientConfig::new(&config.server_url)?
        .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
    CodewireClient::with_token_provider(client_config, config.token_provider()?).map_err(Into::into)
}

pub(crate) fn display_client_error(error: ClientError) -> anyhow::Error {
    if error.code() == ErrorCode::Unauthenticated {
        return anyhow::anyhow!("session expired or invalid");
    }
    error.into()
}

/// One event from a following environment-log stream.
#[derive(Clone, Debug, PartialEq)]
pub enum EnvironmentLogStreamEvent {
    Log(EnvironmentLog),
    Heartbeat,
}

/// Why one environment-log stream connection ended early.
#[derive(Debug)]
pub struct EnvironmentLogStreamFailure {
    pub error: anyhow::Error,
    pub recovery: LogStreamRecovery,
}

/// How a follower recovers from an ended log stream connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStreamRecovery {
    /// The client's whole-call deadline, which also bounds streams, ended the
    /// connection. Resume at once.
    Resume,
    /// A transient failure. Resume after a backoff, within a bounded budget.
    Retry,
    /// Reconnecting cannot help: authorization, a missing environment, a
    /// rejected request, or a row this client cannot decode.
    Fatal,
}

pub(crate) fn log_stream_recovery(code: ErrorCode) -> LogStreamRecovery {
    match code {
        ErrorCode::DeadlineExceeded => LogStreamRecovery::Resume,
        ErrorCode::Unauthenticated
        | ErrorCode::PermissionDenied
        | ErrorCode::NotFound
        | ErrorCode::InvalidArgument
        | ErrorCode::FailedPrecondition
        | ErrorCode::Unimplemented => LogStreamRecovery::Fatal,
        _ => LogStreamRecovery::Retry,
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentPort {
    pub id: String,
    pub environment_id: String,
    pub port: i32,
    pub label: String,
    pub access: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub preview_url: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CreateEnvironmentPortRequest {
    pub port: i32,
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access: String,
}

pub(crate) fn validate_source_selection(
    selection: &EnvironmentSourceSelection,
    exact: bool,
) -> anyhow::Result<()> {
    let spec = codewire_project::ProjectSpec {
        secrets: selection.secrets.clone(),
        credentials: selection.credentials.clone(),
        ..Default::default()
    };
    spec.ensure_platform_compatible()?;
    anyhow::ensure!(
        selection.credentials.is_some() == selection.profile_revision.is_some()
            && selection.profile_revision != Some(0),
        "credential profile selection requires its exact positive revision"
    );
    if exact {
        for reference in [
            (!selection.secrets.project.is_empty()).then_some(selection.secrets.project.as_str()),
            selection
                .credentials
                .as_ref()
                .map(|profile| profile.profile.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            let id = reference.strip_prefix("platform:id:").ok_or_else(|| {
                anyhow::anyhow!("environment source metadata must contain exact platform IDs")
            })?;
            canonical_selection_id(id)?;
        }
    }
    Ok(())
}

fn canonical_selection_id(id: &str) -> anyhow::Result<()> {
    let parsed =
        uuid::Uuid::parse_str(id).map_err(|_| anyhow::anyhow!("invalid source metadata ID"))?;
    anyhow::ensure!(
        !parsed.is_nil() && parsed.to_string() == id,
        "source metadata ID must be canonical and non-nil"
    );
    Ok(())
}

fn source_selection_from_proto(
    value: rpc::EnvironmentSourceSelection,
) -> anyhow::Result<EnvironmentSourceSelection> {
    let spec = codewire_project_proto::from_proto(rpc::ProjectSpec {
        schema_version: codewire_project::PROJECT_SCHEMA_VERSION,
        working_directory: "/workspace".into(),
        secrets: value.secrets,
        credentials: value.credentials,
        ..Default::default()
    })?;
    let selection = EnvironmentSourceSelection {
        secrets: spec.secrets,
        credentials: spec.credentials,
        profile_revision: value.profile_revision,
    };
    validate_source_selection(&selection, true)?;
    Ok(selection)
}

fn source_selection_to_proto(
    value: &EnvironmentSourceSelection,
) -> rpc::EnvironmentSourceSelection {
    let spec = codewire_project_proto::to_proto(codewire_project::ProjectSpec {
        secrets: value.secrets.clone(),
        credentials: value.credentials.clone(),
        ..Default::default()
    });
    rpc::EnvironmentSourceSelection {
        secrets: spec.secrets,
        credentials: spec.credentials,
        profile_revision: value.profile_revision,
        ..Default::default()
    }
}

fn proto_create_environment_request(
    org_id: &str,
    request: &CreateEnvironmentRequest,
) -> rpc::CreateEnvironmentRequest {
    rpc::CreateEnvironmentRequest {
        org_id: org_id.to_string(),
        preset_id: request.preset_id.clone(),
        name: request.name.clone(),
        ttl_seconds: request.ttl_seconds,
        isolation_tier: match request.isolation_tier.as_str() {
            "" | "standard" => rpc::IsolationTier::Standard.into(),
            "confidential" => rpc::IsolationTier::Confidential.into(),
            _ => rpc::IsolationTier::Unspecified.into(),
        },
        project_spec: Some(codewire_project_proto::to_proto(
            request.project_spec.clone(),
        ))
        .into(),
        expected_profile_revision: request.expected_profile_revision,
        confirm_personal_credentials: request.confirm_personal_credentials,
        confirm_personal_secrets: request.confirm_personal_secrets,
        omit_application_previews: request.omit_application_previews,
        network: request.network.clone().unwrap_or_default(),
        ..Default::default()
    }
}

fn legacy_stream_log(message: rpc::StreamLogsResponse) -> anyhow::Result<Option<EnvironmentLog>> {
    match message.event {
        Some(rpc::stream_logs_response::Event::Log(log)) => legacy_environment_log(*log).map(Some),
        Some(rpc::stream_logs_response::Event::Heartbeat(_)) | None => Ok(None),
    }
}

fn legacy_environment_log(value: rpc::EnvironmentLog) -> anyhow::Result<EnvironmentLog> {
    Ok(EnvironmentLog {
        id: value.id,
        environment_id: value.environment_id,
        phase: value.phase,
        status: value.status,
        message: value.message,
        metadata: value
            .metadata
            .into_option()
            .map(serde_json::to_value)
            .transpose()?,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    })
}

fn legacy_prepare_complete(
    complete: rpc::PrepareComplete,
) -> anyhow::Result<PrepareEnvironmentResponse> {
    Ok(PrepareEnvironmentResponse {
        draft: complete
            .draft
            .into_option()
            .map(create_environment_request_from_proto)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("WatchEnvironmentCreate complete event had no draft"))?,
        resolved_preset: complete
            .resolved_preset
            .into_option()
            .map(preset_from_proto)
            .transpose()?,
        repo_config: complete
            .repo_config
            .into_option()
            .map(repo_config_from_proto)
            .transpose()?,
    })
}

fn create_environment_request_from_proto(
    value: rpc::CreateEnvironmentRequest,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let project_spec = value
        .project_spec
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("CreateEnvironmentRequest omitted project_spec"))
        .and_then(|value| codewire_project_proto::from_proto(value).map_err(Into::into))?;
    Ok(CreateEnvironmentRequest {
        preset_id: value.preset_id,
        name: value.name,
        ttl_seconds: value.ttl_seconds,
        isolation_tier: match value.isolation_tier.as_known() {
            Some(rpc::IsolationTier::Confidential) => "confidential".into(),
            Some(rpc::IsolationTier::Standard) | Some(rpc::IsolationTier::Unspecified) | None => {
                String::new()
            }
        },
        project_spec,
        expected_profile_revision: value.expected_profile_revision,
        confirm_personal_credentials: value.confirm_personal_credentials,
        confirm_personal_secrets: value.confirm_personal_secrets,
        omit_application_previews: value.omit_application_previews,
        network: empty_to_none(value.network),
    })
}

fn repo_config_from_proto(value: rpc::RepoConfig) -> anyhow::Result<RepoConfig> {
    let project_spec = value
        .project_spec
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("RepoConfig omitted project_spec"))
        .and_then(|spec| codewire_project_proto::from_proto(spec).map_err(Into::into))?;
    Ok(RepoConfig {
        id: value.id,
        org_id: value.org_id,
        repo_url: value.repo_url,
        project_spec,
        created_by: value.created_by,
        updated_at: value.updated_at,
    })
}

pub(crate) fn legacy_environment_daemon_status(
    value: rpc::EnvironmentDaemonStatus,
) -> EnvironmentDaemonStatus {
    let state = match value.state.as_known() {
        Some(rpc::EnvironmentDaemonState::Unspecified) => "unspecified",
        Some(rpc::EnvironmentDaemonState::Unsupported) => "unsupported",
        Some(rpc::EnvironmentDaemonState::Starting) => "starting",
        Some(rpc::EnvironmentDaemonState::Ready) => "ready",
        Some(rpc::EnvironmentDaemonState::Unhealthy) => "unhealthy",
        Some(rpc::EnvironmentDaemonState::UpgradeRequired) => "upgrade_required",
        None => "unknown",
    };
    EnvironmentDaemonStatus {
        state: state.to_string(),
        protocol_version: value.protocol_version,
        minimum_protocol_version: value.minimum_protocol_version,
        daemon_version: value.daemon_version,
        capabilities: value.capabilities,
        message: value.message,
        diagnostics: value
            .diagnostics
            .into_iter()
            .map(|diagnostic| EnvironmentDaemonDiagnostic {
                name: diagnostic.name,
                healthy: diagnostic.healthy,
                message: diagnostic.message,
            })
            .collect(),
        pod_name: value.pod_name,
    }
}

fn environment_from_proto(value: rpc::Environment) -> anyhow::Result<Environment> {
    let state = match value.state.as_known() {
        Some(rpc::EnvironmentState::Unspecified) => "",
        Some(rpc::EnvironmentState::Pending) => "pending",
        Some(rpc::EnvironmentState::PendingBuild) => "pending_build",
        Some(rpc::EnvironmentState::Building) => "building",
        Some(rpc::EnvironmentState::BuildFailed) => "build_failed",
        Some(rpc::EnvironmentState::PullingSnapshot) => "pulling_snapshot",
        Some(rpc::EnvironmentState::Creating) => "creating",
        Some(rpc::EnvironmentState::Starting) => "starting",
        Some(rpc::EnvironmentState::Running) => "running",
        Some(rpc::EnvironmentState::Stopping) => "stopping",
        Some(rpc::EnvironmentState::Stopped) => "stopped",
        Some(rpc::EnvironmentState::Archiving) => "archiving",
        Some(rpc::EnvironmentState::Archived) => "archived",
        Some(rpc::EnvironmentState::Restoring) => "restoring",
        Some(rpc::EnvironmentState::Resizing) => "resizing",
        Some(rpc::EnvironmentState::Destroying) => "destroying",
        Some(rpc::EnvironmentState::Destroyed) => "destroyed",
        Some(rpc::EnvironmentState::Error) => "error",
        Some(rpc::EnvironmentState::Unknown) | None => "unknown",
    };
    let desired_state = match value.desired_state.as_known() {
        Some(rpc::DesiredState::Unspecified) => "",
        Some(rpc::DesiredState::Started) => "started",
        Some(rpc::DesiredState::Stopped) => "stopped",
        Some(rpc::DesiredState::Destroyed) => "destroyed",
        Some(rpc::DesiredState::Archived) => "archived",
        Some(rpc::DesiredState::Resized) => "resized",
        None => "unknown",
    };
    Ok(Environment {
        operation_generation: value.operation_generation,
        source_selection: value
            .source_selection
            .into_option()
            .map(source_selection_from_proto)
            .transpose()?,
        id: value.id,
        org_id: value.org_id,
        created_by: value.created_by,
        preset_id: value.preset_id,
        environment_type: value.r#type,
        isolation_tier: match value.isolation_tier.as_known() {
            Some(rpc::IsolationTier::Confidential) => "confidential".into(),
            Some(rpc::IsolationTier::Standard) | Some(rpc::IsolationTier::Unspecified) | None => {
                "standard".into()
            }
        },
        name: empty_to_none(value.name),
        state: state.to_string(),
        desired_state: desired_state.to_string(),
        error_reason: empty_to_none(value.error_reason),
        recoverable: value.recoverable,
        state_changed_at: value
            .state_changed_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        retry_count: value.retry_count,
        setup_phase: value.setup_phase,
        setup_complete: value.setup_complete,
        setup_error: empty_to_none(value.setup_error),
        ttl_seconds: value.ttl_seconds,
        shutdown_at: value.shutdown_at.into_option().map(timestamp_to_rfc3339),
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        disk_gb: value.disk_gb,
        total_running_seconds: value.total_running_seconds,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        started_at: value.started_at.into_option().map(timestamp_to_rfc3339),
        stopped_at: value.stopped_at.into_option().map(timestamp_to_rfc3339),
        destroyed_at: value.destroyed_at.into_option().map(timestamp_to_rfc3339),
        protected: value.protected,
        deletion_requested_at: value
            .deletion_requested_at
            .into_option()
            .map(timestamp_to_rfc3339),
        deletion_grace_until: value
            .deletion_grace_until
            .into_option()
            .map(timestamp_to_rfc3339),
        network_state: network_state(value.network_state),
        network_failure: network_failure(value.network_failure),
        network: empty_to_none(value.network),
    })
}

/// The attachment state's name; absent when the environment names no
/// network, `unknown` for a value this CLI does not know.
fn network_state(value: rpc::EnumValue<rpc::NetworkAttachmentState>) -> Option<String> {
    Some(
        match value.as_known() {
            Some(rpc::NetworkAttachmentState::Unspecified) => return None,
            Some(rpc::NetworkAttachmentState::Pending) => "pending",
            Some(rpc::NetworkAttachmentState::Attached) => "attached",
            Some(rpc::NetworkAttachmentState::Failed) => "failed",
            Some(rpc::NetworkAttachmentState::Revoked) => "revoked",
            None => "unknown",
        }
        .to_owned(),
    )
}

fn network_failure(value: rpc::EnumValue<rpc::NetworkAttachmentFailure>) -> Option<String> {
    Some(
        match value.as_known() {
            Some(rpc::NetworkAttachmentFailure::Unspecified) => return None,
            Some(rpc::NetworkAttachmentFailure::MeshUnreachable) => "mesh_unreachable",
            Some(rpc::NetworkAttachmentFailure::NetworkNotFound) => "network_not_found",
            Some(rpc::NetworkAttachmentFailure::NotAMember) => "not_a_member",
            Some(rpc::NetworkAttachmentFailure::NodeNameTaken) => "node_name_taken",
            Some(rpc::NetworkAttachmentFailure::Refused) => "refused",
            None => "unknown",
        }
        .to_owned(),
    )
}

fn legacy_environment_resize_response(
    operation: Option<rpc::EnvironmentResizeOperation>,
    environment: Option<rpc::Environment>,
    poll_interval: Option<rpc::ProtoDuration>,
) -> anyhow::Result<(EnvironmentResizeResult, Option<Duration>)> {
    let operation = operation
        .map(legacy_environment_resize_operation)
        .ok_or_else(|| anyhow::anyhow!("EnvironmentService returned no resize operation"))?;
    let environment = environment
        .map(environment_from_proto)
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("EnvironmentService returned no environment"))?;
    Ok((
        EnvironmentResizeResult {
            operation,
            environment,
        },
        poll_interval.and_then(proto_duration_to_std),
    ))
}

fn legacy_environment_resize_operation(
    value: rpc::EnvironmentResizeOperation,
) -> EnvironmentResizeOperation {
    let state = match value.state.as_known() {
        Some(rpc::EnvironmentResizeOperationState::Pending) => "pending",
        Some(rpc::EnvironmentResizeOperationState::Applying) => "applying",
        Some(rpc::EnvironmentResizeOperationState::Restarting) => "restarting",
        Some(rpc::EnvironmentResizeOperationState::Completed) => "completed",
        Some(rpc::EnvironmentResizeOperationState::Failed) => "failed",
        Some(rpc::EnvironmentResizeOperationState::Unspecified) => "unspecified",
        None => "unknown",
    };
    EnvironmentResizeOperation {
        id: value.id,
        environment_id: value.environment_id,
        request_id: value.request_id,
        previous_resources: value
            .previous_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        desired_resources: value
            .desired_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        last_applied_resources: value
            .last_applied_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        state: state.to_string(),
        disruption_policy: resize_disruption_policy(value.disruption_policy).to_string(),
        planned_mode: resize_execution_mode(value.planned_mode).to_string(),
        applied_mode: resize_execution_mode(value.applied_mode).to_string(),
        pod_replaced: value.pod_replaced,
        failure: value
            .failure
            .into_option()
            .map(|failure| EnvironmentResizeFailure {
                code: failure.code,
                message: failure.message,
            }),
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        updated_at: value
            .updated_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        completed_at: value.completed_at.into_option().map(timestamp_to_rfc3339),
    }
}

fn legacy_environment_resize_plan(value: rpc::EnvironmentResizePlan) -> EnvironmentResizePlan {
    EnvironmentResizePlan {
        previous_resources: value
            .previous_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        desired_resources: value
            .desired_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        execution_mode: resize_execution_mode(value.execution_mode).to_string(),
        active_session_count: value.active_session_count,
        active_sessions_will_be_terminated: value.active_sessions_will_be_terminated,
        reason: value.reason,
        warnings: value.warnings,
    }
}

fn resize_disruption_policy(
    value: rpc::EnumValue<rpc::EnvironmentResizeDisruptionPolicy>,
) -> &'static str {
    match value.as_known() {
        Some(rpc::EnvironmentResizeDisruptionPolicy::LiveOnly) => "live_only",
        Some(rpc::EnvironmentResizeDisruptionPolicy::AllowRestart) => "allow_restart",
        Some(rpc::EnvironmentResizeDisruptionPolicy::Unspecified) => "unspecified",
        None => "unknown",
    }
}

fn resize_execution_mode(
    value: rpc::EnumValue<rpc::EnvironmentResizeExecutionMode>,
) -> &'static str {
    match value.as_known() {
        Some(rpc::EnvironmentResizeExecutionMode::Noop) => "noop",
        Some(rpc::EnvironmentResizeExecutionMode::ApplyOnStart) => "apply_on_start",
        Some(rpc::EnvironmentResizeExecutionMode::InPlace) => "in_place",
        Some(rpc::EnvironmentResizeExecutionMode::Restart) => "restart",
        Some(rpc::EnvironmentResizeExecutionMode::Unspecified) => "unspecified",
        None => "unknown",
    }
}

fn legacy_environment_resize_resources(
    value: rpc::EnvironmentResources,
) -> EnvironmentResizeResources {
    EnvironmentResizeResources {
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        disk_gb: value.disk_gb,
    }
}

fn legacy_environment_access_grant(value: rpc::AccessGrant) -> EnvironmentAccessGrant {
    let permission = match value.permission.as_known() {
        Some(rpc::AccessPermission::Unspecified) => "",
        Some(rpc::AccessPermission::Viewer) => "viewer",
        Some(rpc::AccessPermission::Operator) => "operator",
        Some(rpc::AccessPermission::Owner) => "owner",
        None => "unknown",
    };
    EnvironmentAccessGrant {
        id: value.id,
        environment_id: value.environment_id,
        user_id: value.user_id,
        permission: permission.to_string(),
        granted_by: value.granted_by,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_postgres_text)
            .unwrap_or_default(),
    }
}

fn legacy_environment_port(value: rpc::Port) -> EnvironmentPort {
    let access = match value.access.as_known() {
        Some(rpc::PortAccess::Unspecified) => "",
        Some(rpc::PortAccess::Public) => "public",
        Some(rpc::PortAccess::OrgMembers) => "org_members",
        Some(rpc::PortAccess::Creator) => "creator",
        None => "unknown",
    };
    EnvironmentPort {
        id: value.id,
        environment_id: value.environment_id,
        port: value.port,
        label: value.label,
        access: access.to_string(),
        preview_url: value.preview_url.unwrap_or_default(),
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    }
}

fn legacy_environment_trust_report(value: rpc::EnvironmentTrustReport) -> EnvironmentTrustReport {
    let environment = value.environment.into_option().unwrap_or_default();
    let runtime = value.runtime.into_option().unwrap_or_default();
    let placement = value.placement.into_option().unwrap_or_default();
    let images = value.images.into_option().unwrap_or_default();
    let provenance = value.provenance.into_option().unwrap_or_default();
    let attestation = value.attestation.into_option().unwrap_or_default();
    let trustee = value.trustee.into_option().unwrap_or_default();
    let summary = value.summary.into_option().unwrap_or_default();
    EnvironmentTrustReport {
        environment: TrustReportEnvironment {
            id: environment.id,
            org_id: environment.org_id,
            environment_type: environment.r#type,
            state: environment.state,
            isolation_tier: match environment.isolation_tier.as_known() {
                Some(rpc::IsolationTier::Confidential) => "confidential".to_owned(),
                _ => "standard".to_owned(),
            },
        },
        runtime: TrustReportRuntime {
            profile: runtime.profile,
            runtime_class: runtime.runtime_class,
            handler: runtime.handler,
            confidential: runtime.confidential,
        },
        placement: TrustReportPlacement {
            namespace: empty_to_none(placement.namespace),
            workspace_pod: empty_to_none(placement.workspace_pod),
            pod_ip: empty_to_none(placement.pod_ip),
            node: empty_to_none(placement.node),
            zone: empty_to_none(placement.zone),
            region: empty_to_none(placement.region),
        },
        images: TrustReportImages {
            workspace_image: empty_to_none(images.workspace_image),
            workspace_image_id: empty_to_none(images.workspace_image_id),
            dind_image: empty_to_none(images.dind_image),
            dind_image_id: empty_to_none(images.dind_image_id),
            daemon_init_image: empty_to_none(images.daemon_init_image),
            daemon_init_image_id: empty_to_none(images.daemon_init_image_id),
        },
        provenance: TrustReportProvenance {
            status: provenance.status,
            guest_kernel: empty_to_none(provenance.guest_kernel),
            guest_initrd: empty_to_none(provenance.guest_initrd),
            guest_image: empty_to_none(provenance.guest_image),
            firmware: empty_to_none(provenance.firmware),
            source: empty_to_none(provenance.source),
            notes: provenance.notes,
        },
        attestation: TrustReportAttestation {
            status: attestation.status,
            tee: attestation.tee,
            report_available: attestation.report_available,
            report_source: empty_to_none(attestation.report_source),
            metadata: attestation.metadata.into_iter().collect(),
        },
        trustee: TrustReportTrustee {
            status: trustee.status,
            resource_uri: empty_to_none(trustee.resource_uri),
            reference_values: empty_to_none(trustee.reference_values),
            policy: empty_to_none(trustee.policy),
            evidence_issues: trustee.evidence_issues,
        },
        summary: TrustReportSummary {
            trust_level: summary.trust_level,
            production_verified: summary.production_verified,
            warnings: summary.warnings,
        },
    }
}

fn empty_to_none(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn timestamp_to_rfc3339(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn timestamp_to_postgres_text(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M:%S%.f+00").to_string())
        .unwrap_or_default()
}

fn proto_duration_to_std(duration: rpc::ProtoDuration) -> Option<Duration> {
    let seconds = u64::try_from(duration.seconds).ok()?;
    let nanos = u32::try_from(duration.nanos).ok()?;
    let duration = Duration::new(seconds, nanos);
    (!duration.is_zero()).then_some(duration)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use buffa::Message as _;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const SOURCE_UPDATE_PATH: &str = "/codewire.v1.EnvironmentService/UpdateEnvironmentSources";
    const LIST_ENVIRONMENTS_PATH: &str = "/codewire.v1.EnvironmentService/ListEnvironments";

    #[test]
    fn prepared_create_round_trip_preserves_explicit_no_previews() {
        for omit_application_previews in [false, true] {
            let request = CreateEnvironmentRequest {
                omit_application_previews,
                ..Default::default()
            };
            let wire = proto_create_environment_request("org_test", &request);
            assert_eq!(wire.omit_application_previews, omit_application_previews);
            let restored = create_environment_request_from_proto(wire).unwrap();
            assert_eq!(
                restored.omit_application_previews,
                omit_application_previews
            );
            assert!(restored.project_spec.application_ports.is_empty());
        }
    }

    fn test_client(server: &MockServer) -> EnvironmentClient {
        EnvironmentClient {
            inner: CodewireClient::with_http(
                ClientConfig::new(server.uri()).unwrap(),
                rpc::StaticTokenProvider::new("synthetic-source-test-token").unwrap(),
                reqwest::Client::new(),
            )
            .unwrap(),
        }
    }

    fn selected_sources() -> EnvironmentSourceSelection {
        EnvironmentSourceSelection {
            secrets: codewire_project::SecretBindings {
                project: "platform:id:11111111-1111-4111-8111-111111111111".into(),
                organization: true,
                user: Some(codewire_project::StoragePlacement::Platform),
            },
            credentials: Some(codewire_project::CredentialBinding {
                profile: "platform:id:22222222-2222-4222-8222-222222222222".into(),
            }),
            profile_revision: Some(9_007_199_254_740_993),
        }
    }

    #[tokio::test]
    async fn environment_list_sends_the_exact_destroyed_selection() {
        for include_destroyed in [false, true] {
            let server = MockServer::start().await;
            let request = rpc::ListEnvironmentsRequest {
                org_id: "org_test".into(),
                include_destroyed,
                ..Default::default()
            };
            Mock::given(method("POST"))
                .and(path(LIST_ENVIRONMENTS_PATH))
                .and(body_bytes(request.encode_to_vec()))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(rpc::ListEnvironmentsResponse::default().encode_to_vec()),
                )
                .expect(1)
                .mount(&server)
                .await;

            let environments = test_client(&server)
                .list_environments("org_test", include_destroyed)
                .await
                .unwrap();
            assert!(environments.is_empty());
        }
    }

    const PROJECT_SPEC_PATH: &str = "/codewire.v1.EnvironmentService/GetEnvironmentProjectSpec";

    async fn project_spec_server(response: rpc::GetEnvironmentProjectSpecResponse) -> MockServer {
        let server = MockServer::start().await;
        let request = rpc::GetEnvironmentProjectSpecRequest {
            org_id: "org_test".into(),
            environment_id: "env_test".into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(PROJECT_SPEC_PATH))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn project_spec_read_returns_the_saved_spec_and_withheld_names() {
        let saved = codewire_project::ProjectSpec {
            install_command: "npm ci".into(),
            credentials: Some(codewire_project::CredentialBinding {
                profile: "platform:id:22222222-2222-4222-8222-222222222222".into(),
            }),
            ..Default::default()
        };
        let server = project_spec_server(rpc::GetEnvironmentProjectSpecResponse {
            project_spec: Some(codewire_project_proto::to_proto(saved.clone())).into(),
            withheld_environment_keys: vec!["API_URL".into(), "NODE_ENV".into()],
            ..Default::default()
        })
        .await;
        let (spec, withheld) = test_client(&server)
            .get_environment_project_spec("org_test", "env_test")
            .await
            .unwrap();
        assert_eq!(spec, saved);
        assert_eq!(withheld, ["API_URL", "NODE_ENV"]);
    }

    #[tokio::test]
    async fn project_spec_read_refuses_values_and_a_missing_spec() {
        let mut with_values = codewire_project::ProjectSpec::default();
        with_values
            .environment
            .insert("API_URL".into(), "synthetic-canary-never-exported".into());
        for (response, expected) in [
            (
                rpc::GetEnvironmentProjectSpecResponse {
                    project_spec: Some(codewire_project_proto::to_proto(with_values.clone()))
                        .into(),
                    ..Default::default()
                },
                "refusing to export them",
            ),
            (
                rpc::GetEnvironmentProjectSpecResponse::default(),
                "returned no project spec",
            ),
        ] {
            let server = project_spec_server(response).await;
            let error = test_client(&server)
                .get_environment_project_spec("org_test", "env_test")
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert!(!error.to_string().contains("synthetic-canary"), "{error}");
        }
    }

    #[test]
    fn environment_source_metadata_preserves_absence_empty_and_exact_revisions() {
        let missing = environment_from_proto(rpc::Environment::default()).unwrap();
        assert_eq!(
            missing.source_selection, None,
            "absence is unsupported, not an empty selection"
        );
        for selection in [EnvironmentSourceSelection::default(), selected_sources()] {
            let environment = environment_from_proto(rpc::Environment {
                operation_generation: 9_007_199_254_740_995,
                source_selection: Some(source_selection_to_proto(&selection)).into(),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(environment.operation_generation, 9_007_199_254_740_995);
            assert_eq!(environment.source_selection.as_ref(), Some(&selection));
            let json = serde_json::to_string(&environment).unwrap();
            assert_eq!(
                serde_json::from_str::<Environment>(&json).unwrap(),
                environment
            );
        }
    }

    #[test]
    fn create_ack_requires_exact_organization_and_source_selection() {
        let selection = selected_sources();
        let request = CreateEnvironmentRequest {
            project_spec: codewire_project::ProjectSpec {
                secrets: selection.secrets.clone(),
                credentials: selection.credentials.clone(),
                ..Default::default()
            },
            expected_profile_revision: selection.profile_revision,
            ..Default::default()
        };
        let acknowledged = Environment {
            id: "33333333-3333-4333-8333-333333333333".into(),
            org_id: "org_123".into(),
            source_selection: Some(selection),
            ..Default::default()
        };

        validate_created_environment(&acknowledged, "org_123", &request).unwrap();

        let mut wrong = acknowledged.clone();
        wrong.source_selection = None;
        assert!(validate_created_environment(&wrong, "org_123", &request).is_err());

        let mut wrong = acknowledged;
        wrong.org_id = "org_other".into();
        assert!(validate_created_environment(&wrong, "org_123", &request).is_err());
    }

    #[tokio::test]
    async fn hosted_profile_resolution_uses_only_personal_metadata_and_pins_exact_revision() {
        let server = MockServer::start().await;
        let request = rpc::GetAccessProfileRequest {
            selector: Some(rpc::get_access_profile_request::Selector::Name(
                "work".into(),
            )),
            ..Default::default()
        };
        let response = rpc::GetAccessProfileResponse {
            access_profile: Some(rpc::AccessProfile {
                id: "22222222-2222-4222-8222-222222222222".into(),
                name: "work".into(),
                revision: 9_007_199_254_740_993,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.AccessProfileService/GetAccessProfile"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        let profile = test_client(&server)
            .resolve_credential_profile("platform:user/work")
            .await
            .unwrap();
        assert_eq!(profile.id, "22222222-2222-4222-8222-222222222222");
        assert_eq!(profile.revision, 9_007_199_254_740_993);
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "no material or alternate-store RPC"
        );
    }

    #[tokio::test]
    async fn hosted_profile_resolution_rejects_local_and_unsupported_org_before_transport() {
        let server = MockServer::start().await;
        let client = test_client(&server);
        for selector in [
            "local:work",
            "platform:organization/work",
            "platform:id:00000000-0000-0000-0000-000000000000",
        ] {
            assert!(
                client.resolve_credential_profile(selector).await.is_err(),
                "{selector}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn hosted_profile_resolution_rejects_mismatched_id_or_name_without_fallback() {
        for selector in [
            "platform:user/work",
            "platform:id:22222222-2222-4222-8222-222222222222",
        ] {
            let server = MockServer::start().await;
            let response = rpc::GetAccessProfileResponse {
                access_profile: Some(rpc::AccessProfile {
                    id: "33333333-3333-4333-8333-333333333333".into(),
                    name: "other".into(),
                    revision: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            };
            Mock::given(method("POST"))
                .and(path("/codewire.v1.AccessProfileService/GetAccessProfile"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(response.encode_to_vec()),
                )
                .expect(1)
                .mount(&server)
                .await;
            assert!(
                test_client(&server)
                    .resolve_credential_profile(selector)
                    .await
                    .is_err()
            );
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[test]
    fn source_selection_rejects_unpinned_noncanonical_and_unknown_metadata() {
        for reference in [
            "work",
            "platform:work",
            "local:work",
            "platform:id:00000000-0000-0000-0000-000000000000",
            "platform:id:AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        ] {
            let mut selection = selected_sources();
            selection.credentials.as_mut().unwrap().profile = reference.into();
            assert!(
                validate_source_selection(&selection, true).is_err(),
                "{reference}"
            );
        }
        for revision in [None, Some(0)] {
            let mut selection = selected_sources();
            selection.profile_revision = revision;
            assert!(validate_source_selection(&selection, true).is_err());
        }
        let mut selection = selected_sources();
        selection.credentials = None;
        assert!(validate_source_selection(&selection, true).is_err());
        for user in [
            rpc::ProjectStoragePlacement::Unspecified.into(),
            rpc::EnumValue::Unknown(99),
            rpc::ProjectStoragePlacement::Local.into(),
        ] {
            assert!(
                source_selection_from_proto(rpc::EnvironmentSourceSelection {
                    secrets: Some(rpc::ProjectSecretBindings {
                        user: Some(user),
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                })
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn source_update_sends_complete_exact_cas_and_explicit_empty_clear_once() {
        let server = MockServer::start().await;
        let request = UpdateEnvironmentSourcesRequest {
            expected_operation_generation: 9_007_199_254_740_995,
            expected: selected_sources(),
            replacement: EnvironmentSourceSelection::default(),
            allow_restart: true,
            confirm_personal_credentials: false,
            confirm_personal_secrets: false,
        };
        let expected_wire = rpc::UpdateEnvironmentSourcesRequest {
            org_id: "org_test".into(),
            environment_id: "env_test".into(),
            expected_operation_generation: request.expected_operation_generation,
            expected: Some(source_selection_to_proto(&request.expected)).into(),
            replacement: Some(source_selection_to_proto(&request.replacement)).into(),
            allow_restart: true,
            ..Default::default()
        };
        let response = rpc::UpdateEnvironmentSourcesResponse {
            environment_id: "env_test".into(),
            operation_generation: request.expected_operation_generation,
            selection: Some(source_selection_to_proto(&request.replacement)).into(),
            outcome: rpc::EnvironmentSourcesUpdateOutcome::RestartRequired.into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(SOURCE_UPDATE_PATH))
            .and(header(
                "authorization",
                "Bearer synthetic-source-test-token",
            ))
            .and(body_bytes(expected_wire.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = test_client(&server)
            .update_environment_sources("org_test", "env_test", &request)
            .await
            .unwrap();
        assert_eq!(result.selection, EnvironmentSourceSelection::default());
        assert_eq!(
            result.operation_generation,
            request.expected_operation_generation
        );
        assert_eq!(
            result.outcome,
            EnvironmentSourcesUpdateOutcome::RestartRequired
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn source_update_conflicts_are_not_refetched_or_retried() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(SOURCE_UPDATE_PATH))
            .respond_with(
                ResponseTemplate::new(409)
                    .insert_header("content-type", "application/json")
                    .set_body_json(
                        serde_json::json!({"code": "aborted", "message": "selection changed"}),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let request = UpdateEnvironmentSourcesRequest {
            expected_operation_generation: 7,
            expected: selected_sources(),
            replacement: selected_sources(),
            allow_restart: false,
            confirm_personal_credentials: true,
            confirm_personal_secrets: true,
        };
        assert!(
            test_client(&server)
                .update_environment_sources("org_test", "env_test", &request)
                .await
                .is_err()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn source_update_rejects_incomplete_or_mismatched_success_responses() {
        for mutation in 0..5 {
            let server = MockServer::start().await;
            let request = UpdateEnvironmentSourcesRequest {
                expected_operation_generation: 7,
                expected: selected_sources(),
                replacement: selected_sources(),
                allow_restart: false,
                confirm_personal_credentials: true,
                confirm_personal_secrets: true,
            };
            let mut response = rpc::UpdateEnvironmentSourcesResponse {
                environment_id: "env_test".into(),
                operation_generation: 7,
                selection: Some(source_selection_to_proto(&request.replacement)).into(),
                outcome: rpc::EnvironmentSourcesUpdateOutcome::Unchanged.into(),
                ..Default::default()
            };
            match mutation {
                0 => response.environment_id = "other_environment".into(),
                1 => response.operation_generation += 1,
                2 => response.selection = None.into(),
                3 => {
                    response.selection = Some(source_selection_to_proto(
                        &EnvironmentSourceSelection::default(),
                    ))
                    .into()
                }
                4 => response.outcome = rpc::EnumValue::Unknown(99),
                _ => unreachable!(),
            }
            Mock::given(method("POST"))
                .and(path(SOURCE_UPDATE_PATH))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/proto")
                        .set_body_bytes(response.encode_to_vec()),
                )
                .expect(1)
                .mount(&server)
                .await;
            assert!(
                test_client(&server)
                    .update_environment_sources("org_test", "env_test", &request)
                    .await
                    .is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[tokio::test]
    async fn source_update_rejects_invalid_inputs_before_transport() {
        let server = MockServer::start().await;
        let mut request = UpdateEnvironmentSourcesRequest {
            expected_operation_generation: 0,
            expected: selected_sources(),
            replacement: selected_sources(),
            allow_restart: false,
            confirm_personal_credentials: true,
            confirm_personal_secrets: true,
        };
        let client = test_client(&server);
        assert!(
            client
                .update_environment_sources("org_test", "env_test", &request)
                .await
                .is_err()
        );
        request.expected_operation_generation = 7;
        request.replacement.profile_revision = None;
        assert!(
            client
                .update_environment_sources("org_test", "env_test", &request)
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn environment_connect_adapter_round_trips_the_complete_canonical_project_spec() {
        let request = CreateEnvironmentRequest {
            preset_id: Some("preset_123".to_string()),
            name: Some("builder".to_string()),
            expected_profile_revision: Some(9_007_199_254_740_993),
            confirm_personal_credentials: true,
            confirm_personal_secrets: true,
            project_spec: codewire_project::parse_project_yaml(
                r#"
version: 1
image: ghcr.io/example/workspace@sha256:abc
repositories:
  - source: https://git.example/codewire
    revision: deadbeef
    destination: /workspace/codewire
working_directory: /workspace/codewire
install_command: cargo fetch
startup_script: cargo test
environment: {RUST_LOG: info}
agents: {install: false, tools: [codex]}
skills:
  - {source: repository, path: .agents/skills/rust, agents: [codex]}
  - {source: user, name: personal}
ports: [{port: 8080, label: web, access: public}]
cpu: "2"
memory: "8Gi"
disk: "40Gi"
secrets: {project: platform:development, organization: true, user: platform}
credentials: {profile: platform:user/work}
"#,
            )
            .unwrap()
            .spec,
            ..CreateEnvironmentRequest::default()
        };
        let round_trip = create_environment_request_from_proto(proto_create_environment_request(
            "org_123", &request,
        ))
        .unwrap();
        assert_eq!(round_trip, request);

        let environment = environment_from_proto(rpc::Environment {
            id: "env_123".into(),
            org_id: "org_123".into(),
            created_by: "user_123".into(),
            r#type: "sandbox".into(),
            name: "builder".into(),
            state: rpc::EnvironmentState::Running.into(),
            desired_state: rpc::DesiredState::Started.into(),
            state_changed_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .unwrap();
        let value = serde_json::to_value(environment).unwrap();
        assert_eq!(value["id"], "env_123");
        assert_eq!(value["org_id"], "org_123");
        assert_eq!(value["name"], "builder");
        assert_eq!(value["state"], "running");
        assert_eq!(value["desired_state"], "started");
        assert_eq!(value["created_at"], "2026-01-01T00:00:00Z");
        assert_eq!(
            proto_duration_to_std(rpc::ProtoDuration {
                seconds: 2,
                nanos: 500_000_000,
                ..Default::default()
            }),
            Some(Duration::new(2, 500_000_000))
        );
        assert_eq!(proto_duration_to_std(rpc::ProtoDuration::default()), None);

        let grant = legacy_environment_access_grant(rpc::AccessGrant {
            id: "grant_123".into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                nanos: 123_456_000,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        assert_eq!(grant.created_at, "2026-01-01 00:00:00.123456+00");
    }

    #[test]
    fn environment_setup_metadata_is_independent_from_running_state() {
        let running = environment_from_proto(rpc::Environment {
            state: rpc::EnvironmentState::Running.into(),
            setup_phase: 4,
            setup_complete: false,
            setup_error: "startup failed".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(running.state, "running");
        assert_eq!(running.setup_phase, 4);
        assert!(!running.setup_complete);
        assert_eq!(running.setup_error.as_deref(), Some("startup failed"));
        let running_json = serde_json::to_value(&running).unwrap();
        assert_eq!(running_json["state"], "running");
        assert_eq!(running_json["setup_phase"], 4);
        assert_eq!(running_json["setup_complete"], false);
        assert_eq!(running_json["setup_error"], "startup failed");

        let complete = environment_from_proto(rpc::Environment {
            state: rpc::EnvironmentState::Running.into(),
            setup_phase: 7,
            setup_complete: true,
            ..Default::default()
        })
        .unwrap();
        assert!(complete.setup_complete);
        assert_eq!(complete.setup_phase, 7);
        assert_eq!(complete.setup_error, None);
        let complete_json = serde_json::to_value(complete).unwrap();
        assert_eq!(complete_json["setup_complete"], true);
        assert_eq!(complete_json.get("setup_error"), None);
    }

    #[test]
    fn environment_inputs_fail_when_required_project_specs_are_absent() {
        let create_error =
            create_environment_request_from_proto(rpc::CreateEnvironmentRequest::default())
                .unwrap_err();
        assert!(create_error.to_string().contains("omitted project_spec"));

        let repo_error = repo_config_from_proto(rpc::RepoConfig::default()).unwrap_err();
        assert!(repo_error.to_string().contains("omitted project_spec"));

        let complete_error = legacy_prepare_complete(rpc::PrepareComplete::default()).unwrap_err();
        assert!(complete_error.to_string().contains("had no draft"));
    }

    #[test]
    fn log_adapter_preserves_cli_output_shape() {
        let log = legacy_stream_log(rpc::StreamLogsResponse {
            event: Some(rpc::stream_logs_response::Event::Log(Box::new(
                rpc::EnvironmentLog {
                    id: "log_123".to_string(),
                    environment_id: "env_123".to_string(),
                    phase: "setup".to_string(),
                    status: "running".to_string(),
                    message: "installing dependencies".to_string(),
                    created_at: Some(rpc::Timestamp {
                        seconds: 1_767_225_600,
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert_eq!(log.id, "log_123");
        assert_eq!(log.message, "installing dependencies");
        assert_eq!(log.created_at, "2026-01-01T00:00:00Z");
        assert_eq!(log.metadata, None);
        assert!(
            legacy_stream_log(rpc::StreamLogsResponse {
                event: Some(rpc::stream_logs_response::Event::Heartbeat(
                    Default::default()
                )),
                ..Default::default()
            })
            .unwrap()
            .is_none()
        );
    }

    const STREAM_LOGS_PATH: &str = "/codewire.v1.EnvironmentService/StreamLogs";

    fn connect_envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![flags];
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    async fn mount_log_stream(
        server: &MockServer,
        messages: &[rpc::StreamLogsResponse],
        end: serde_json::Value,
    ) {
        let mut body = Vec::new();
        for message in messages {
            body.extend(connect_envelope(0, &message.encode_to_vec()));
        }
        body.extend(connect_envelope(2, &serde_json::to_vec(&end).unwrap()));
        Mock::given(method("POST"))
            .and(path(STREAM_LOGS_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/connect+proto")
                    .set_body_bytes(body),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn log_follow_resumes_after_the_cursor_and_surfaces_heartbeats() {
        let server = MockServer::start().await;
        let mut log = rpc::EnvironmentLog {
            id: "log_3".into(),
            environment_id: "env_test".into(),
            phase: "git_clone".into(),
            status: "progress".into(),
            message: "Cloning repositories".into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        log.metadata = Some(
            serde_json::from_value(serde_json::json!({
                "repo_index": 1,
                "repo_count": 2,
                "stage": "receiving_objects",
                "percent": 45
            }))
            .unwrap(),
        )
        .into();
        mount_log_stream(
            &server,
            &[
                rpc::StreamLogsResponse {
                    event: Some(rpc::stream_logs_response::Event::Heartbeat(
                        Default::default(),
                    )),
                    ..Default::default()
                },
                rpc::StreamLogsResponse {
                    event: Some(rpc::stream_logs_response::Event::Log(Box::new(log))),
                    ..Default::default()
                },
            ],
            serde_json::json!({}),
        )
        .await;

        let mut events = Vec::new();
        test_client(&server)
            .follow_environment_log_stream("org_test", "env_test", Some("log_2"), |event| {
                events.push(event);
                true
            })
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let body = &requests[0].body;
        assert_eq!(body[0], 0, "uncompressed request envelope");
        let mut payload = &body[5..];
        let request = rpc::StreamLogsRequest::decode(&mut payload).unwrap();
        assert_eq!(request.org_id, "org_test");
        assert_eq!(request.environment_id, "env_test");
        assert!(request.follow);
        assert_eq!(request.after_log_id, "log_2");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0], EnvironmentLogStreamEvent::Heartbeat);
        let EnvironmentLogStreamEvent::Log(log) = &events[1] else {
            panic!("expected a log row");
        };
        assert_eq!(log.id, "log_3");
        assert_eq!(log.created_at, "2026-01-01T00:00:00Z");
        // google.protobuf.Struct carries numbers as doubles.
        let metadata = log.metadata.as_ref().unwrap();
        assert!(metadata["repo_index"].is_f64(), "{metadata}");
        assert_eq!(metadata["repo_index"].as_f64(), Some(1.0));
        assert_eq!(metadata["stage"], "receiving_objects");
    }

    #[tokio::test]
    async fn log_follow_failures_carry_their_recovery() {
        for (code, recovery) in [
            ("deadline_exceeded", LogStreamRecovery::Resume),
            ("unavailable", LogStreamRecovery::Retry),
            ("internal", LogStreamRecovery::Retry),
            ("unauthenticated", LogStreamRecovery::Fatal),
            ("permission_denied", LogStreamRecovery::Fatal),
            ("not_found", LogStreamRecovery::Fatal),
        ] {
            let server = MockServer::start().await;
            mount_log_stream(
                &server,
                &[],
                serde_json::json!({"error": {"code": code, "message": "synthetic"}}),
            )
            .await;
            let failure = test_client(&server)
                .follow_environment_log_stream("org_test", "env_test", None, |_| true)
                .await
                .unwrap_err();
            assert_eq!(failure.recovery, recovery, "{code}");
            let request = &server.received_requests().await.unwrap()[0];
            let mut payload = &request.body[5..];
            let request = rpc::StreamLogsRequest::decode(&mut payload).unwrap();
            assert_eq!(request.after_log_id, "", "{code}");
        }
    }

    #[test]
    fn port_adapter_preserves_cli_json_shape() {
        let port = legacy_environment_port(rpc::Port {
            id: "port_123".into(),
            environment_id: "env_123".into(),
            port: 8080,
            label: "web".into(),
            access: rpc::PortAccess::Public.into(),
            preview_url: Some("https://preview.example".into()),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        assert_eq!(
            serde_json::to_value(port).expect("port JSON"),
            serde_json::json!({
                "id": "port_123",
                "environment_id": "env_123",
                "port": 8080,
                "label": "web",
                "access": "public",
                "preview_url": "https://preview.example",
                "created_at": "2026-01-01T00:00:00Z"
            })
        );
    }
}
