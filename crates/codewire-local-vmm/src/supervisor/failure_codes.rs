//! The closed codes a failed create and a failed lifecycle operation record,
//! one per [`SupervisorError`]: names only, never an error's Display, Debug
//! or details.

use super::seed_placeholders::PlatformPlaceholdersRefusal;
use super::*;

pub(super) fn create_failure_code(error: &SupervisorError) -> &'static str {
    match error {
        SupervisorError::UnsafeRuntimeArtifactStore { .. } => UNSAFE_RUNTIME_ARTIFACT_STORE_CODE,
        SupervisorError::AlreadyExists(_) => "create_name_taken",
        SupervisorError::GuestDockerToolingMissing => "create_guest_docker_tooling_missing",
        SupervisorError::GuestSetupFailed => "create_guest_setup_failed",
        SupervisorError::GuestWorkspaceFailed => "create_guest_workspace_failed",
        SupervisorError::HostPortUnavailable => "create_host_port_unavailable",
        SupervisorError::CredentialBrokerUnavailable { .. } => {
            "create_credential_broker_unavailable"
        }
        SupervisorError::Interception(refusal) => refusal.create_code(),
        #[cfg(target_os = "macos")]
        SupervisorError::VmStartRefused => "create_vm_start_refused",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperMissing(_) => "create_vz_helper_missing",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperUnentitled(_) => "create_vz_helper_unentitled",
        SupervisorError::CredentialAuthorityUnavailable => {
            "create_credential_authority_unavailable"
        }
        SupervisorError::EnvironmentAccessUnavailable => "create_access_unavailable",
        SupervisorError::PlatformPlaceholders(refusal) => match refusal {
            PlatformPlaceholdersRefusal::Unsupported => "create_platform_placeholders_unsupported",
            PlatformPlaceholdersRefusal::Unavailable(_) => {
                "create_platform_placeholders_unavailable"
            }
        },
        SupervisorError::UnclearedDisk(refusal) => refusal.create_code(),
        SupervisorError::BoundSecrets(refusal) => refusal.create_code(),
        SupervisorError::EnvironmentAccessBindingRejected(code) => match code {
            tonic::Code::InvalidArgument => "create_access_binding_invalid",
            tonic::Code::NotFound => "create_access_binding_not_found",
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
                "create_access_binding_denied"
            }
            tonic::Code::FailedPrecondition => "create_access_binding_precondition",
            tonic::Code::DataLoss => "create_access_binding_metadata",
            _ => "create_access_binding_rejected",
        },
        SupervisorError::RegistryResolver(error) => match error {
            RegistryResolverError::Client => "create_registry_client",
            RegistryResolverError::Transport => "create_registry_transport",
            RegistryResolverError::AuthenticationRequired => "create_registry_auth_required",
            RegistryResolverError::AuthenticationFailed => "create_registry_auth_failed",
            RegistryResolverError::NotFound => "create_registry_not_found",
            RegistryResolverError::RegistryResponse => "create_registry_response",
            RegistryResolverError::UnsafeUrl
            | RegistryResolverError::UnsafeRedirect
            | RegistryResolverError::TooManyRedirects => "create_registry_url_rejected",
            RegistryResolverError::UnsupportedHostArchitecture
            | RegistryResolverError::PlatformUnavailable
            | RegistryResolverError::AmbiguousPlatform
            | RegistryResolverError::UnsupportedPlatform => "create_registry_platform",
            RegistryResolverError::Reference(_) => "create_registry_reference",
            RegistryResolverError::Content(ContentStoreError::Stream) => {
                "create_registry_blob_stream"
            }
            RegistryResolverError::Content(
                ContentStoreError::SizeMismatch { .. }
                | ContentStoreError::DigestMismatch
                | ContentStoreError::ExistingBlobInvalid,
            ) => "create_registry_blob_integrity",
            RegistryResolverError::Content(_) => "create_registry_content_store",
            _ => "create_registry_admission",
        },
        SupervisorError::RegistryReference(_) => "create_registry_reference",
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged) => {
            "create_direct_share_changed"
        }
        SupervisorError::SkillSnapshot(_) => "create_skill_snapshot",
        SupervisorError::WorkspaceGenerationProvisionTask => "create_workspace_generation_task",
        SupervisorError::WorkspaceGeneration => "create_workspace_generation_invalid",
        SupervisorError::ContentStore(_) => "create_content_store",
        SupervisorError::Path(_) | SupervisorError::Io { .. } => "create_filesystem",
        SupervisorError::InvalidState => "create_state_invalid",
        SupervisorError::InvalidConfiguration => "create_configuration_invalid",
        SupervisorError::Workspace(WorkspaceError::NestedRepositoryTracked { .. }) => {
            "create_nested_repository_tracked"
        }
        _ => "create_failed",
    }
}

pub(super) fn lifecycle_failure_cause(error: &SupervisorError) -> &'static str {
    match error {
        SupervisorError::InvalidConfiguration => "invalid_configuration",
        SupervisorError::SocketDir(_) => "socket_dir_unavailable",
        SupervisorError::SupervisorNotReachable { .. } => "supervisor_not_reachable",
        SupervisorError::SocketPathTooLong { .. } => "socket_path_too_long",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperMissing(_) => "vz_helper_missing",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperUnentitled(_) => "vz_helper_unentitled",
        SupervisorError::InvalidRequest => "invalid_request",
        SupervisorError::ReservedPort(_) => "reserved_port",
        SupervisorError::AlreadyExists(_) => "already_exists",
        SupervisorError::InvalidState => "invalid_state",
        SupervisorError::UnownedWorkspaceStaging(_) => "unowned_workspace_staging",
        SupervisorError::SecretInState => "secret_in_state",
        SupervisorError::CredentialAuthorityUnavailable => "credential_authority_unavailable",
        SupervisorError::WorkloadSecretDeliveryUnavailable => {
            "workload_secret_delivery_unavailable"
        }
        SupervisorError::EnvironmentAccessUnavailable => "access_unavailable",
        SupervisorError::PlatformPlaceholders(refusal) => refusal.code(),
        SupervisorError::UnclearedDisk(refusal) => refusal.code(),
        SupervisorError::BoundSecrets(refusal) => refusal.code(),
        SupervisorError::EnvironmentAccessBindingRejected(code) => match code {
            tonic::Code::InvalidArgument => "access_binding_invalid",
            tonic::Code::NotFound => "access_binding_not_found",
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => "access_binding_denied",
            tonic::Code::FailedPrecondition => "access_binding_precondition",
            tonic::Code::DataLoss => "access_binding_metadata",
            _ => "access_binding_rejected",
        },
        SupervisorError::NotFound(_) => "not_found",
        SupervisorError::NotRunning => "not_running",
        SupervisorError::Orphaned => "orphaned",
        SupervisorError::AlreadyRunning => "already_running",
        SupervisorError::SpawnSupervisor => "supervisor_spawn",
        SupervisorError::SupervisorStartTimeout => "supervisor_start_timeout",
        SupervisorError::EndpointNotReplaced(_) => "endpoint_not_replaced",
        SupervisorError::SupervisorProtocolUnavailable => "supervisor_protocol_unavailable",
        SupervisorError::SupervisorProtocolMismatch { .. } => "supervisor_protocol_mismatch",
        SupervisorError::InvalidSupervisorInfo => "supervisor_info_invalid",
        SupervisorError::SupervisorInfoUnavailable => "supervisor_info_unavailable",
        SupervisorError::SupervisorConfigurationMismatch => "supervisor_configuration_mismatch",
        SupervisorError::Retiring => "supervisor_retiring",
        SupervisorError::RetireRefused(_) => "supervisor_retire_refused",
        SupervisorError::NetworkPolicyStore(_) => "supervisor_network_policy_store",
        SupervisorError::NetworkPolicySelection(_) => "network_policy_selection",
        SupervisorError::SpawnRunner => "runner_spawn",
        SupervisorError::RunnerStartTimeout => "runner_start_timeout",
        SupervisorError::RunnerAdoption => "runner_adoption",
        SupervisorError::RunnerUnavailable => "runner_unavailable",
        SupervisorError::RunnerProtocolUnsupported => "runner_protocol_unsupported",
        SupervisorError::RunnerExitTimeout => "runner_exit_timeout",
        SupervisorError::RunnerRetirement => "runner_retirement",
        SupervisorError::InvalidRunnerResponse => "runner_response_invalid",
        SupervisorError::ArtifactGenerationChanged => "artifact_generation_changed",
        SupervisorError::VmStart(_) => "vm_start",
        SupervisorError::GuestDockerToolingMissing => "guest_docker_tooling_missing",
        SupervisorError::GuestSetupFailed => "guest_setup_failed",
        SupervisorError::GuestWorkspaceFailed => "guest_workspace_failed",
        SupervisorError::HostPortUnavailable => "host_port_unavailable",
        SupervisorError::CredentialBrokerUnavailable { .. } => "credential_broker_unavailable",
        SupervisorError::Interception(refusal) => refusal.code(),
        #[cfg(target_os = "macos")]
        SupervisorError::VmStartRefused => "vm_start_refused",
        SupervisorError::VmStop => "vm_stop",
        SupervisorError::VmResize => "vm_resize",
        SupervisorError::VmDelete => "vm_delete",
        SupervisorError::WorkspaceProvisionTask => "workspace_provision_task",
        SupervisorError::WorkspaceGenerationProvisionTask => "workspace_generation_task",
        SupervisorError::OperationTerminal => "operation_terminal",
        SupervisorError::Serve => "serve",
        SupervisorError::Runner(_) => "runner",
        SupervisorError::Artifact(_) => "artifact",
        SupervisorError::ArtifactStore | SupervisorError::UnsafeRuntimeArtifactStore { .. } => {
            "artifact_store"
        }
        SupervisorError::CwRuntime(_) => "cw_runtime",
        SupervisorError::CwRuntimeProvisionTask => "cw_runtime_task",
        SupervisorError::ReplacementPreflight(_) => "replacement_preflight",
        SupervisorError::RunnerService(_) => "runner_service",
        SupervisorError::Recovery(_) => "process_recovery",
        SupervisorError::Workspace(_) => "workspace",
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged) => {
            "direct_share_changed"
        }
        SupervisorError::WorkspacePlan(_) => "workspace_plan",
        SupervisorError::RegistryReference(_) => "registry_reference",
        SupervisorError::RegistryResolver(_) => "registry",
        SupervisorError::ContentStore(_) => "content_store",
        SupervisorError::SetupPack(_) => "setup_pack",
        SupervisorError::SkillSnapshot(_) => "skill_snapshot",
        SupervisorError::WorkspaceGeneration => "workspace_generation",
        SupervisorError::Generation(_) => "root_generation",
        SupervisorError::Uds(_) => "local_socket",
        SupervisorError::Path(_) => "path",
        SupervisorError::State(_) => "vm_state",
        SupervisorError::Store(_) => "store",
        SupervisorError::Io { .. } => "filesystem",
    }
}
