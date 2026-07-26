//! Rust-owned OpenAPI preview for orchestration routes.
//!
//! This service-local preview records the orchestration service's Rust DTOs
//! and route metadata for the merged canonical contract without changing
//! runtime handlers.

use codewire_api_contract::{Method, OpenApiBuilder, Operation, with_standard_health_routes};

use super::admin::{
    AdminEnvironmentLifecycleJournalEntry, AdminEnvironmentStartupSummary,
    AdminEnvironmentStartupTimings, AdminOrg, AdminStatsResponse, AuditLogEntry,
};
use super::api_keys::{ApiKey, CreateApiKeyBody, CreateApiKeyResponse, UpdateApiKeyBody};
use super::assignments::UpdateMemberAssignmentsBody;
use super::create::CreateEnvironmentBody;
use super::detect::DetectionResult;
use super::environments::{Environment, EnvironmentPort, ExtendTtlBody};
use super::git_credentials::{CreateGitCredentialBody, GitCredential, UpdateGitCredentialBody};
use super::github::{GitHubConfig, GitHubRepo, GitHubStatus, OkResponse, SaveGitHubTokenBody};
use super::login_keys::{AddLoginKeyBody, LoginKeyResponse};
use super::organizations::{
    AcceptInvitationResult, CreateOrgBody, InviteMemberBody, OrgInvitation, OrgMember,
    OrgWithMembers, OrgWithRole, Organization, OrganizationDeletionResponse, UpdateRoleBody,
};
use super::ports::CreatePortBody;
use super::prepare::{DetectRequest, EnvironmentCreateOptionsBody, PresetWire};
use super::presets::{CreatePresetBody, UpdatePresetBody};
use super::proxy::{ExecBody, ExecResult, FileEntry};
use super::secret_projects::{
    CreateProjectBody, RenameProjectSecretBody, SecretProject, SetProjectSecretBody,
};
use super::secrets::{
    ListSecretsResponse, RenameSecretBody, RenameUserSecretBody, SetSecretBody, SetUserSecretBody,
    StatusResponse,
};
use super::ssh_keys::{GitIdentityResponse, SSHKeyResponse, UpdateGitIdentityBody};
use super::trust_report::EnvironmentTrustReport;

pub fn rust_openapi_preview() -> serde_json::Value {
    with_standard_health_routes(OpenApiBuilder::new("Codewire Rust API Preview", "0.1.0"))
        .operation(
            "/api/v1/admin/stats",
            Method::Get,
            Operation::new("getAdminStats")
                .tag("admin")
                .summary("Get admin statistics")
                .json_response::<AdminStatsResponse>(200, "Admin statistics", "AdminStatsResponse"),
        )
        .operation(
            "/api/v1/admin/organizations",
            Method::Get,
            Operation::new("listAdminOrganizations")
                .tag("admin")
                .summary("List organizations for admins")
                .json_array_response::<AdminOrg>(200, "Admin organizations", "AdminOrg"),
        )
        .operation(
            "/api/v1/admin/audit-logs",
            Method::Get,
            Operation::new("listAuditLogs")
                .tag("admin")
                .summary("List audit logs")
                .query_param(
                    "limit",
                    serde_json::json!({
                        "type": "integer",
                        "format": "int64",
                        "default": 50,
                        "maximum": 200,
                    }),
                )
                .query_param(
                    "offset",
                    serde_json::json!({
                        "type": "integer",
                        "format": "int64",
                        "default": 0,
                    }),
                )
                .query_param("action", serde_json::json!({"type": "string"}))
                .query_param("severity", serde_json::json!({"type": "string"}))
                .json_array_response::<AuditLogEntry>(200, "Audit logs", "AuditLogEntry"),
        )
        .operation(
            "/api/v1/admin/environments/{environmentId}/lifecycle-journal",
            Method::Get,
            Operation::new("listAdminEnvironmentLifecycleJournal")
                .tag("admin")
                .summary("List environment lifecycle journal")
                .path_param("environmentId")
                .query_param(
                    "limit",
                    serde_json::json!({
                        "type": "integer",
                        "format": "int64",
                        "default": 100,
                        "maximum": 500,
                    }),
                )
                .json_array_response::<AdminEnvironmentLifecycleJournalEntry>(
                    200,
                    "Environment lifecycle journal",
                    "AdminEnvironmentLifecycleJournalEntry",
                ),
        )
        .operation(
            "/api/v1/admin/environments/startup-summary",
            Method::Get,
            Operation::new("getAdminEnvironmentStartupSummary")
                .tag("admin")
                .summary("Get environment startup summary")
                .query_param(
                    "window_minutes",
                    serde_json::json!({
                        "type": "integer",
                        "format": "int64",
                        "default": 240,
                        "minimum": 5,
                        "maximum": 10080,
                    }),
                )
                .json_response::<AdminEnvironmentStartupSummary>(
                    200,
                    "Environment startup summary",
                    "AdminEnvironmentStartupSummary",
                ),
        )
        .operation(
            "/api/v1/admin/environments/{environmentId}/startup-timings",
            Method::Get,
            Operation::new("getAdminEnvironmentStartupTimings")
                .tag("admin")
                .summary("Get environment startup timings")
                .path_param("environmentId")
                .json_response::<AdminEnvironmentStartupTimings>(
                    200,
                    "Environment startup timings",
                    "AdminEnvironmentStartupTimings",
                ),
        )
        .operation(
            "/api/v1/organizations",
            Method::Get,
            Operation::new("listOrganizations")
                .tag("organizations")
                .summary("List organizations")
                .json_array_response::<OrgWithRole>(200, "Organizations", "OrgWithRole"),
        )
        .operation(
            "/api/v1/organizations",
            Method::Post,
            Operation::new("createOrganization")
                .tag("organizations")
                .summary("Create organization")
                .json_request::<CreateOrgBody>("CreateOrgRequest")
                .json_response::<Organization>(201, "Organization", "Organization"),
        )
        .operation(
            "/api/v1/organizations/{orgId}",
            Method::Get,
            Operation::new("getOrganization")
                .tag("organizations")
                .summary("Get organization")
                .path_param("orgId")
                .json_response::<OrgWithMembers>(
                    200,
                    "Organization with members",
                    "OrgWithMembers",
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}",
            Method::Delete,
            Operation::new("deleteOrganization")
                .tag("organizations")
                .summary("Delete organization")
                .path_param("orgId")
                .empty_response(204, "No Content")
                .json_response::<OrganizationDeletionResponse>(
                    202,
                    "Organization deletion accepted",
                    "OrganizationDeletionResponse",
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}/members",
            Method::Get,
            Operation::new("listOrganizationMembers")
                .tag("organizations")
                .summary("List organization members")
                .path_param("orgId")
                .json_array_response::<OrgMember>(200, "Organization members", "OrgMember"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/members/{userId}",
            Method::Put,
            Operation::new("updateOrganizationMemberRole")
                .tag("organizations")
                .summary("Update organization member role")
                .path_param("orgId")
                .path_param("userId")
                .json_request::<UpdateRoleBody>("UpdateRoleBody")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/members/{userId}",
            Method::Delete,
            Operation::new("removeOrganizationMember")
                .tag("organizations")
                .summary("Remove organization member")
                .path_param("orgId")
                .path_param("userId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/invitations",
            Method::Get,
            Operation::new("listOrganizationInvitations")
                .tag("organizations")
                .summary("List organization invitations")
                .path_param("orgId")
                .json_array_response::<OrgInvitation>(
                    200,
                    "Organization invitations",
                    "OrgInvitation",
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}/invitations",
            Method::Post,
            Operation::new("createOrganizationInvitation")
                .tag("organizations")
                .summary("Create organization invitation")
                .path_param("orgId")
                .json_request::<InviteMemberBody>("InviteMemberBody")
                .json_response::<OrgInvitation>(201, "Organization invitation", "OrgInvitation"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/invitations/{invitationId}",
            Method::Delete,
            Operation::new("revokeOrganizationInvitation")
                .tag("organizations")
                .summary("Revoke organization invitation")
                .path_param("orgId")
                .path_param("invitationId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/invitations/{token}",
            Method::Get,
            Operation::new("getInvitationByToken")
                .tag("organizations")
                .summary("Get invitation by token")
                .path_param("token")
                .json_response::<OrgInvitation>(200, "Organization invitation", "OrgInvitation"),
        )
        .operation(
            "/api/v1/invitations/{token}/accept",
            Method::Post,
            Operation::new("acceptInvitation")
                .tag("organizations")
                .summary("Accept invitation")
                .path_param("token")
                .json_response::<AcceptInvitationResult>(
                    200,
                    "Invitation acceptance result",
                    "AcceptInvitationResult",
                ),
        )
        .operation(
            "/api/v1/user/login-keys",
            Method::Get,
            Operation::new("listLoginKeys")
                .tag("login-keys")
                .summary("List user login keys")
                .json_array_response::<LoginKeyResponse>(
                    200,
                    "User login keys",
                    "LoginKeyResponse",
                ),
        )
        .operation(
            "/api/v1/user/login-keys",
            Method::Post,
            Operation::new("addLoginKey")
                .tag("login-keys")
                .summary("Add user login key")
                .json_request::<AddLoginKeyBody>("AddLoginKeyBody")
                .json_response::<LoginKeyResponse>(201, "User login key", "LoginKeyResponse"),
        )
        .operation(
            "/api/v1/user/login-keys/{id}",
            Method::Delete,
            Operation::new("deleteLoginKey")
                .tag("login-keys")
                .summary("Delete user login key")
                .path_param("id")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/api-keys",
            Method::Get,
            Operation::new("listAPIKeys")
                .tag("api-keys")
                .summary("List API keys")
                .path_param("orgId")
                .json_array_response::<ApiKey>(200, "API keys", "APIKey"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/api-keys",
            Method::Post,
            Operation::new("createAPIKey")
                .tag("api-keys")
                .summary("Create API key")
                .path_param("orgId")
                .json_request::<CreateApiKeyBody>("CreateAPIKeyBody")
                .json_response::<CreateApiKeyResponse>(
                    201,
                    "Created API key",
                    "CreateAPIKeyResponse",
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}/api-keys/{keyId}",
            Method::Patch,
            Operation::new("updateAPIKey")
                .tag("api-keys")
                .summary("Update API key")
                .path_param("orgId")
                .path_param("keyId")
                .json_request::<UpdateApiKeyBody>("UpdateAPIKeyBody")
                .json_response::<ApiKey>(200, "API key", "APIKey"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/api-keys/{keyId}",
            Method::Delete,
            Operation::new("deleteAPIKey")
                .tag("api-keys")
                .summary("Delete API key")
                .path_param("orgId")
                .path_param("keyId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments",
            Method::Get,
            Operation::new("listEnvironments")
                .tag("environments")
                .summary("List environments for an organization")
                .path_param("orgId")
                .query_param("type", serde_json::json!({"type": "string"}))
                .query_param("state", serde_json::json!({"type": "string"}))
                .query_param("include_destroyed", serde_json::json!({"type": "boolean"}))
                .json_array_response::<Environment>(200, "OK", "Environment"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments",
            Method::Post,
            Operation::new("createEnvironment")
                .tag("environments")
                .summary("Create a new environment")
                .path_param("orgId")
                .json_request::<CreateEnvironmentBody>("CreateEnvironmentBody")
                .json_response::<Environment>(201, "Created", "Environment"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}",
            Method::Get,
            Operation::new("getEnvironment")
                .tag("environments")
                .summary("Get an environment by ID")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<Environment>(200, "OK", "Environment"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/trust-report",
            Method::Get,
            Operation::new("getEnvironmentTrustReport")
                .tag("environments")
                .summary("Get environment trust report")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<EnvironmentTrustReport>(200, "OK", "EnvironmentTrustReport"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}",
            Method::Delete,
            Operation::new("deleteEnvironment")
                .tag("environments")
                .summary("Destroy an environment")
                .path_param("orgId")
                .path_param("envId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/stop",
            Method::Post,
            Operation::new("stopEnvironment")
                .tag("environments")
                .summary("Stop a running environment")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<StatusResponse>(200, "OK", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/start",
            Method::Post,
            Operation::new("startEnvironment")
                .tag("environments")
                .summary("Start a stopped environment")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<StatusResponse>(200, "OK", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/protect",
            Method::Post,
            Operation::new("protectEnvironment")
                .tag("environments")
                .summary("Protect an environment from deletion")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<StatusResponse>(200, "OK", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/unprotect",
            Method::Post,
            Operation::new("unprotectEnvironment")
                .tag("environments")
                .summary("Remove deletion protection from an environment")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<StatusResponse>(200, "OK", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/cancel-deletion",
            Method::Post,
            Operation::new("cancelEnvironmentDeletion")
                .tag("environments")
                .summary("Cancel pending environment deletion")
                .path_param("orgId")
                .path_param("envId")
                .json_response::<StatusResponse>(200, "OK", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/extend-ttl",
            Method::Post,
            Operation::new("extendEnvironmentTTL")
                .tag("environments")
                .summary("Extend the time-to-live of an environment")
                .path_param("orgId")
                .path_param("envId")
                .json_request::<ExtendTtlBody>("ExtendTTLInputBody")
                .json_response::<StatusResponse>(200, "OK", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/ports",
            Method::Get,
            Operation::new("listEnvironmentPorts")
                .tag("environment-ports")
                .summary("List environment ports")
                .path_param("orgId")
                .path_param("envId")
                .json_array_response::<EnvironmentPort>(200, "OK", "EnvironmentPort"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/ports",
            Method::Post,
            Operation::new("createEnvironmentPort")
                .tag("environment-ports")
                .summary("Create an environment port")
                .path_param("orgId")
                .path_param("envId")
                .json_request::<CreatePortBody>("CreatePortBody")
                .json_response::<EnvironmentPort>(201, "Created", "EnvironmentPort"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/ports/{portId}",
            Method::Delete,
            Operation::new("deleteEnvironmentPort")
                .tag("environment-ports")
                .summary("Delete an environment port")
                .path_param("orgId")
                .path_param("envId")
                .path_param("portId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/exec",
            Method::Post,
            Operation::new("execInEnvironment")
                .tag("environments")
                .summary("Execute a command in a sandbox environment")
                .path_param("orgId")
                .path_param("envId")
                .json_request::<ExecBody>("ExecBody")
                .json_response::<ExecResult>(200, "OK", "ExecResult"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environments/{envId}/files",
            Method::Get,
            Operation::new("listFiles")
                .tag("environments")
                .summary("List files in a sandbox environment")
                .path_param("orgId")
                .path_param("envId")
                .query_param("path", serde_json::json!({"type": "string"}))
                .json_array_response::<FileEntry>(200, "OK", "FileEntry"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/members/{memberId}/assignments",
            Method::Get,
            Operation::new("getMemberAssignments")
                .tag("assignments")
                .summary("Get assignments for a member")
                .path_param("orgId")
                .path_param("memberId")
                .json_response_schema(
                    200,
                    "OK",
                    serde_json::json!({
                        "type": "array",
                        "items": { "type": "string" },
                    }),
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}/members/{memberId}/assignments",
            Method::Put,
            Operation::new("updateMemberAssignments")
                .tag("assignments")
                .summary("Update assignments for a member")
                .path_param("orgId")
                .path_param("memberId")
                .json_request::<UpdateMemberAssignmentsBody>("UpdateMemberAssignmentsInputBody")
                .json_response_schema(
                    200,
                    "OK",
                    serde_json::json!({
                        "type": "array",
                        "items": { "type": "string" },
                    }),
                ),
        )
        .operation(
            "/api/v1/environment-create/detect",
            Method::Post,
            Operation::new("detectEnvironmentRepo")
                .tag("environment-create")
                .summary("Analyze a repository and detect workspace configuration")
                .json_request::<DetectRequest>("DetectRequest")
                .json_response::<DetectionResult>(200, "OK", "DetectionResult"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/environment-create/options",
            Method::Get,
            Operation::new("getEnvironmentCreateOptions")
                .tag("environment-create")
                .summary("Get shared environment creation options for UI and CLI")
                .path_param("orgId")
                .json_response::<EnvironmentCreateOptionsBody>(
                    200,
                    "OK",
                    "EnvironmentCreateOptionsBody",
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}/presets",
            Method::Get,
            Operation::new("listPresets")
                .tag("presets")
                .summary("List presets for an organization")
                .path_param("orgId")
                .json_array_response::<PresetWire>(200, "Presets", "Preset"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/presets",
            Method::Post,
            Operation::new("createPreset")
                .tag("presets")
                .summary("Create preset")
                .path_param("orgId")
                .json_request::<CreatePresetBody>("CreatePresetBody")
                .json_response::<PresetWire>(201, "Preset", "Preset"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/presets/{presetId}",
            Method::Get,
            Operation::new("getPreset")
                .tag("presets")
                .summary("Get preset")
                .path_param("orgId")
                .path_param("presetId")
                .json_response::<PresetWire>(200, "Preset", "Preset"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/presets/{presetId}",
            Method::Patch,
            Operation::new("updatePreset")
                .tag("presets")
                .summary("Update preset")
                .path_param("orgId")
                .path_param("presetId")
                .json_request::<UpdatePresetBody>("UpdatePresetBody")
                .json_response::<PresetWire>(200, "Preset", "Preset"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/presets/{presetId}",
            Method::Delete,
            Operation::new("deletePreset")
                .tag("presets")
                .summary("Delete preset")
                .path_param("orgId")
                .path_param("presetId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/github/config",
            Method::Get,
            Operation::new("getGitHubConfig")
                .tag("github")
                .summary("Get GitHub app config")
                .json_response::<GitHubConfig>(200, "GitHub app config", "GitHubConfig"),
        )
        .operation(
            "/api/v1/github/status",
            Method::Get,
            Operation::new("getGitHubStatus")
                .tag("github")
                .summary("Get GitHub connection status")
                .json_response::<GitHubStatus>(200, "GitHub connection status", "GitHubStatus"),
        )
        .operation(
            "/api/v1/github/repos",
            Method::Get,
            Operation::new("listGitHubRepos")
                .tag("github")
                .summary("List GitHub repositories")
                .query_param(
                    "page",
                    serde_json::json!({"type": "integer", "format": "int32"}),
                )
                .query_param(
                    "per_page",
                    serde_json::json!({"type": "integer", "format": "int32"}),
                )
                .query_param("search", serde_json::json!({"type": "string"}))
                .json_array_response::<GitHubRepo>(200, "GitHub repositories", "GitHubRepo"),
        )
        .operation(
            "/api/v1/github/token",
            Method::Post,
            Operation::new("saveGitHubToken")
                .tag("github")
                .summary("Save GitHub token")
                .json_request::<SaveGitHubTokenBody>("SaveGitHubTokenBody")
                .json_response::<OkResponse>(200, "GitHub token saved", "OkResponse"),
        )
        .operation(
            "/api/v1/github/token",
            Method::Delete,
            Operation::new("deleteGitHubToken")
                .tag("github")
                .summary("Delete GitHub token")
                .json_response::<OkResponse>(200, "GitHub token deleted", "OkResponse"),
        )
        .operation(
            "/api/v1/git-credentials",
            Method::Get,
            Operation::new("listGitCredentials")
                .tag("git-credentials")
                .summary("List git credentials")
                .json_array_response::<GitCredential>(200, "Git credentials", "GitCredential"),
        )
        .operation(
            "/api/v1/git-credentials",
            Method::Post,
            Operation::new("createGitCredential")
                .tag("git-credentials")
                .summary("Create git credential")
                .json_request::<CreateGitCredentialBody>("CreateGitCredentialBody")
                .json_response::<GitCredential>(201, "Git credential", "GitCredential"),
        )
        .operation(
            "/api/v1/git-credentials/{credentialId}",
            Method::Put,
            Operation::new("updateGitCredential")
                .tag("git-credentials")
                .summary("Update git credential")
                .path_param("credentialId")
                .json_request::<UpdateGitCredentialBody>("UpdateGitCredentialBody")
                .json_response::<GitCredential>(200, "Git credential", "GitCredential"),
        )
        .operation(
            "/api/v1/git-credentials/{credentialId}",
            Method::Delete,
            Operation::new("deleteGitCredential")
                .tag("git-credentials")
                .summary("Delete git credential")
                .path_param("credentialId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/user/ssh-key",
            Method::Get,
            Operation::new("getSSHKey")
                .tag("ssh-keys")
                .summary("Get user SSH key")
                .json_response::<SSHKeyResponse>(200, "User SSH key", "SSHKeyResponse"),
        )
        .operation(
            "/api/v1/user/ssh-key/regenerate",
            Method::Post,
            Operation::new("regenerateSSHKey")
                .tag("ssh-keys")
                .summary("Regenerate user SSH key")
                .json_response::<SSHKeyResponse>(200, "User SSH key", "SSHKeyResponse"),
        )
        .operation(
            "/api/v1/user/git-identity",
            Method::Get,
            Operation::new("getGitIdentity")
                .tag("git-identity")
                .summary("Get user git identity")
                .json_response::<GitIdentityResponse>(
                    200,
                    "User git identity",
                    "GitIdentityResponse",
                ),
        )
        .operation(
            "/api/v1/user/git-identity",
            Method::Put,
            Operation::new("updateGitIdentity")
                .tag("git-identity")
                .summary("Update user git identity")
                .json_request::<UpdateGitIdentityBody>("UpdateGitIdentityBody")
                .json_response::<GitIdentityResponse>(
                    200,
                    "User git identity",
                    "GitIdentityResponse",
                ),
        )
        .operation(
            "/api/v1/secrets",
            Method::Get,
            Operation::new("listSecrets")
                .tag("secrets")
                .summary("List organization secrets")
                .query_param("org_id", serde_json::json!({"type": "string"}))
                .json_response::<ListSecretsResponse>(
                    200,
                    "Organization secrets",
                    "ListSecretsResponse",
                ),
        )
        .operation(
            "/api/v1/secrets",
            Method::Put,
            Operation::new("setSecret")
                .tag("secrets")
                .summary("Set organization secret")
                .json_request::<SetSecretBody>("SetSecretInputBody")
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .operation(
            "/api/v1/secrets/{key}",
            Method::Delete,
            Operation::new("deleteSecret")
                .tag("secrets")
                .summary("Delete organization secret")
                .path_param("key")
                .query_param("org_id", serde_json::json!({"type": "string"}))
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .operation(
            "/api/v1/secrets/{key}/rename",
            Method::Post,
            Operation::new("renameSecret")
                .tag("secrets")
                .summary("Rename organization secret")
                .path_param("key")
                .json_request::<RenameSecretBody>("RenameSecretInputBody")
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .operation(
            "/api/v1/user/secrets",
            Method::Get,
            Operation::new("listUserSecrets")
                .tag("secrets")
                .summary("List user secrets")
                .json_response::<ListSecretsResponse>(200, "User secrets", "ListSecretsResponse"),
        )
        .operation(
            "/api/v1/user/secrets",
            Method::Put,
            Operation::new("setUserSecret")
                .tag("secrets")
                .summary("Set user secret")
                .json_request::<SetUserSecretBody>("SetUserSecretInputBody")
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .operation(
            "/api/v1/user/secrets/{key}",
            Method::Delete,
            Operation::new("deleteUserSecret")
                .tag("secrets")
                .summary("Delete user secret")
                .path_param("key")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/user/secrets/{key}/rename",
            Method::Post,
            Operation::new("renameUserSecret")
                .tag("secrets")
                .summary("Rename user secret")
                .path_param("key")
                .json_request::<RenameUserSecretBody>("RenameUserSecretInputBody")
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects",
            Method::Get,
            Operation::new("listSecretProjects")
                .tag("secret-projects")
                .summary("List secret projects")
                .path_param("orgId")
                .json_array_response::<SecretProject>(200, "Secret projects", "SecretProject"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects",
            Method::Post,
            Operation::new("createSecretProject")
                .tag("secret-projects")
                .summary("Create secret project")
                .path_param("orgId")
                .json_request::<CreateProjectBody>("CreateSecretProjectInputBody")
                .json_response::<SecretProject>(201, "Secret project", "SecretProject"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects/{projectId}",
            Method::Delete,
            Operation::new("deleteSecretProject")
                .tag("secret-projects")
                .summary("Delete secret project")
                .path_param("orgId")
                .path_param("projectId")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects/{projectId}/secrets",
            Method::Get,
            Operation::new("listProjectSecrets")
                .tag("secret-projects")
                .summary("List project secrets")
                .path_param("orgId")
                .path_param("projectId")
                .json_response::<ListSecretsResponse>(
                    200,
                    "Project secrets",
                    "ListSecretsResponse",
                ),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects/{projectId}/secrets",
            Method::Put,
            Operation::new("setProjectSecret")
                .tag("secret-projects")
                .summary("Set project secret")
                .path_param("orgId")
                .path_param("projectId")
                .json_request::<SetProjectSecretBody>("SetProjectSecretInputBody")
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects/{projectId}/secrets/{key}",
            Method::Delete,
            Operation::new("deleteProjectSecret")
                .tag("secret-projects")
                .summary("Delete project secret")
                .path_param("orgId")
                .path_param("projectId")
                .path_param("key")
                .empty_response(204, "No Content"),
        )
        .operation(
            "/api/v1/organizations/{orgId}/secret-projects/{projectId}/secrets/{key}/rename",
            Method::Post,
            Operation::new("renameProjectSecret")
                .tag("secret-projects")
                .summary("Rename project secret")
                .path_param("orgId")
                .path_param("projectId")
                .path_param("key")
                .json_request::<RenameProjectSecretBody>("RenameProjectSecretBody")
                .json_response::<StatusResponse>(200, "Secret status", "StatusResponse"),
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_contains_registered_route_families() {
        let doc = rust_openapi_preview();

        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(
            doc["paths"]["/healthz"]["get"]["responses"]["200"]["content"]["text/plain"]["schema"]
                ["type"],
            "string"
        );
        assert_eq!(
            doc["paths"]["/readyz"]["get"]["responses"]["503"]["content"]["text/plain"]["schema"]["type"],
            "string"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/stats"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/AdminStatsResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/audit-logs"]["get"]["parameters"][0]["name"],
            "limit"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/audit-logs"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["items"]["$ref"],
            "#/components/schemas/AuditLogEntry"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/environments/{environmentId}/lifecycle-journal"]["get"]["parameters"]
                [0]["name"],
            "environmentId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/environments/startup-summary"]["get"]["parameters"][0]["name"],
            "window_minutes"
        );
        assert_eq!(
            doc["paths"]["/api/v1/admin/environments/{environmentId}/startup-timings"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/AdminEnvironmentStartupTimings"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/CreateOrgRequest"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["items"]["$ref"],
            "#/components/schemas/OrgWithRole"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/OrgWithMembers"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}"]["delete"]["responses"]["204"]["description"],
            "No Content"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}"]["delete"]["responses"]["202"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/OrganizationDeletionResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/invitations"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/InviteMemberBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/invitations"]["post"]["responses"]["201"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/OrgInvitation"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/members/{userId}"]["put"]["responses"]["204"]
                ["description"],
            "No Content"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/login-keys"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/AddLoginKeyBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/login-keys/{id}"]["delete"]["parameters"][0]["name"],
            "id"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/api-keys"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/CreateAPIKeyBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/api-keys/{keyId}"]["patch"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/APIKey"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/api-keys/{keyId}"]["delete"]["parameters"]
                [1]["name"],
            "keyId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments"]["get"]["parameters"][1]["name"],
            "type"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/Environment"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/CreateEnvironmentBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Environment"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/trust-report"]["get"]
                ["operationId"],
            "getEnvironmentTrustReport"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/trust-report"]["get"]
                ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/EnvironmentTrustReport"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}"]["delete"]["responses"]
                ["204"]["description"],
            "No Content"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/stop"]["post"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/StatusResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/start"]["post"]["operationId"],
            "startEnvironment"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/protect"]["post"]["parameters"]
                [1]["name"],
            "envId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/unprotect"]["post"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/StatusResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/cancel-deletion"]["post"]
                ["operationId"],
            "cancelEnvironmentDeletion"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/extend-ttl"]["post"]["requestBody"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ExtendTTLInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/ports"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/EnvironmentPort"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/ports"]["post"]["requestBody"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/CreatePortBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/ports/{portId}"]["delete"]
                ["parameters"][2]["name"],
            "portId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/exec"]["post"]["requestBody"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ExecBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/exec"]["post"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ExecResult"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/files"]["get"]["parameters"]
                [2]["name"],
            "path"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environments/{envId}/files"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/FileEntry"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/members/{memberId}/assignments"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["items"]["type"],
            "string"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/members/{memberId}/assignments"]["put"]["requestBody"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/UpdateMemberAssignmentsInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/members/{memberId}/assignments"]["put"]["parameters"]
                [1]["name"],
            "memberId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/environment-create/detect"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/DetectRequest"
        );
        assert_eq!(
            doc["paths"]["/api/v1/environment-create/detect"]["post"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/DetectionResult"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/environment-create/options"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/EnvironmentCreateOptionsBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/presets"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/Preset"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/presets"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/CreatePresetBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/presets/{presetId}"]["patch"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Preset"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/presets/{presetId}"]["delete"]["parameters"]
                [1]["name"],
            "presetId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/github/config"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/GitHubConfig"
        );
        assert_eq!(
            doc["paths"]["/api/v1/github/repos"]["get"]["parameters"][1]["name"],
            "per_page"
        );
        assert_eq!(
            doc["paths"]["/api/v1/github/repos"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["items"]["$ref"],
            "#/components/schemas/GitHubRepo"
        );
        assert_eq!(
            doc["paths"]["/api/v1/github/token"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/SaveGitHubTokenBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/github/token"]["delete"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/OkResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/git-credentials"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/CreateGitCredentialBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/git-credentials/{credentialId}"]["put"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/GitCredential"
        );
        assert_eq!(
            doc["paths"]["/api/v1/git-credentials/{credentialId}"]["delete"]["parameters"][0]["name"],
            "credentialId"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/ssh-key"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/SSHKeyResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/ssh-key/regenerate"]["post"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/SSHKeyResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/git-identity"]["put"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/UpdateGitIdentityBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/git-identity"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/GitIdentityResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/secrets"]["get"]["parameters"][0]["name"],
            "org_id"
        );
        assert_eq!(
            doc["paths"]["/api/v1/secrets"]["put"]["requestBody"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/SetSecretInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/secrets/{key}"]["delete"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/StatusResponse"
        );
        assert_eq!(
            doc["paths"]["/api/v1/user/secrets/{key}"]["delete"]["responses"]["204"]["description"],
            "No Content"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/secret-projects"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/CreateSecretProjectInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/secret-projects"]["get"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["items"]["$ref"],
            "#/components/schemas/SecretProject"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/secret-projects/{projectId}/secrets"]["put"]
                ["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/SetProjectSecretInputBody"
        );
        assert_eq!(
            doc["paths"]["/api/v1/organizations/{orgId}/secret-projects/{projectId}/secrets/{key}/rename"]
                ["post"]["parameters"][2]["name"],
            "key"
        );
    }

    #[test]
    fn preview_components_come_from_rust_dtos() {
        let doc = rust_openapi_preview();

        assert_eq!(
            doc["components"]["schemas"]["OrgWithRole"]["properties"]["billing_plan"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["AdminStatsResponse"]["properties"]["total_environments"]
                ["type"],
            "integer"
        );
        assert_eq!(
            doc["components"]["schemas"]["AdminOrg"]["properties"]["slug"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["AuditLogEntry"]["properties"]["user_email"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["AdminEnvironmentStartupSummary"]["properties"]["phase_durations"]
                ["items"]["$ref"],
            "#/components/schemas/AdminEnvironmentStartupPhaseSummary"
        );
        assert_eq!(
            doc["components"]["schemas"]["AdminEnvironmentStartupTimings"]["properties"]["timings"]
                ["items"]["$ref"],
            "#/components/schemas/AdminEnvironmentStartupTiming"
        );
        assert_eq!(
            doc["components"]["schemas"]["OrgWithMembers"]["properties"]["members"]["items"]["$ref"],
            "#/components/schemas/OrgMember"
        );
        assert_eq!(
            doc["components"]["schemas"]["Organization"]["properties"]["slug"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateOrgRequest"]["properties"]["name"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateOrgRequest"]["required"],
            serde_json::json!(["name", "slug"])
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdateRoleBody"]["required"],
            serde_json::json!(["role"])
        );
        assert_eq!(
            doc["components"]["schemas"]["AcceptInvitationResult"]["properties"]["orgId"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["OrgInvitation"]["properties"]["accepted_at"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["InviteMemberBody"]["properties"]["assignments"]["items"]
                ["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["InviteMemberBody"]["required"],
            serde_json::json!(["email", "role"])
        );
        assert_eq!(
            doc["components"]["schemas"]["LoginKeyResponse"]["properties"]["fingerprint"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["AddLoginKeyBody"]["properties"]["public_key"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["APIKey"]["properties"]["key_prefix"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateAPIKeyResponse"]["properties"]["key"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdateAPIKeyBody"]["properties"]["disabled"]["type"],
            serde_json::json!(["boolean", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["Environment"]["properties"]["type"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["Environment"]["properties"]["preset_id"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["Environment"]["properties"]["ports"]["items"]["$ref"],
            "#/components/schemas/EnvironmentPort"
        );
        assert_eq!(
            doc["components"]["schemas"]["EnvironmentPort"]["properties"]["preview_url"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["EnvironmentTrustReport"]["properties"]["summary"]["$ref"],
            "#/components/schemas/TrustReportSummary"
        );
        assert_eq!(
            doc["components"]["schemas"]["EnvironmentTrustReport"]["properties"]["provenance"]["$ref"],
            "#/components/schemas/TrustReportProvenance"
        );
        assert_eq!(
            doc["components"]["schemas"]["TrustReportRuntime"]["properties"]["profile"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["TrustReportSummary"]["properties"]["production_verified"]
                ["type"],
            "boolean"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreatePortBody"]["properties"]["port"]["type"],
            "integer"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreatePortBody"]["required"],
            serde_json::json!(["port", "label"])
        );
        assert_eq!(
            doc["components"]["schemas"]["ExtendTTLInputBody"]["properties"]["additional_seconds"]
                ["type"],
            "integer"
        );
        assert_eq!(
            doc["components"]["schemas"]["ExecBody"]["properties"]["command"]["items"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["ExecResult"]["properties"]["stdout"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["FileEntry"]["properties"]["is_dir"]["type"],
            "boolean"
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdateMemberAssignmentsInputBody"]["properties"]["assignments"]
                ["items"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdateMemberAssignmentsInputBody"]["required"],
            serde_json::json!(["assignments"])
        );
        assert_eq!(
            doc["components"]["schemas"]["DetectRequest"]["properties"]["repo_url"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["DetectRequest"]["required"],
            serde_json::json!(["repo_url"])
        );
        assert_eq!(
            doc["components"]["schemas"]["DetectionResult"]["properties"]["app_ports"]["items"]["$ref"],
            "#/components/schemas/AppPort"
        );
        assert_eq!(
            doc["components"]["schemas"]["EnvironmentCreateOptionsBody"]["properties"]["github_status"]
                ["$ref"],
            "#/components/schemas/EnvironmentCreateGitHubStatus"
        );
        assert_eq!(
            doc["components"]["schemas"]["EnvironmentCreateGitHubStatus"]["properties"]["connected"]
                ["type"],
            "boolean"
        );
        assert_eq!(
            doc["components"]["schemas"]["Preset"]["properties"]["default_setup_config"]["anyOf"]
                [0]["$ref"],
            "#/components/schemas/SetupConfig"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreatePresetBody"]["properties"]["agents"]["items"]["$ref"],
            "#/components/schemas/SetupAgentInput"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreatePresetBody"]["required"],
            serde_json::json!(["name"])
        );
        assert!(
            doc["components"]["schemas"]["UpdatePresetBody"]
                .get("required")
                .is_none()
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdatePresetBody"]["properties"]["image"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["AppPort"]["properties"]["port"]["type"],
            "integer"
        );
        assert_eq!(
            doc["components"]["schemas"]["GitHubConfig"]["properties"]["client_id"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["GitHubStatus"]["properties"]["installation_id"]["type"],
            serde_json::json!(["integer", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["GitHubRepo"]["properties"]["private"]["type"],
            "boolean"
        );
        assert_eq!(
            doc["components"]["schemas"]["SaveGitHubTokenBody"]["properties"]["access_token"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["SaveGitHubTokenBody"]["required"],
            serde_json::json!(["access_token"])
        );
        assert_eq!(
            doc["components"]["schemas"]["OkResponse"]["properties"]["ok"]["type"],
            "boolean"
        );
        assert_eq!(
            doc["components"]["schemas"]["GitCredential"]["properties"]["auth_type"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateGitCredentialBody"]["properties"]["password"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateGitCredentialBody"]["required"],
            serde_json::json!(["name", "host", "auth_type", "password"])
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdateGitCredentialBody"]["properties"]["username"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["SSHKeyResponse"]["properties"]["fingerprint"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["GitIdentityResponse"]["properties"]["git_email"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["UpdateGitIdentityBody"]["properties"]["git_name"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert_eq!(
            doc["components"]["schemas"]["SecretMetadata"]["properties"]["key"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["ListSecretsResponse"]["properties"]["secrets"]["items"]["$ref"],
            "#/components/schemas/SecretMetadata"
        );
        assert_eq!(
            doc["components"]["schemas"]["StatusResponse"]["properties"]["status"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["SetSecretInputBody"]["properties"]["value"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["SetSecretInputBody"]["required"],
            serde_json::json!(["org_id", "key", "value"])
        );
        assert_eq!(
            doc["components"]["schemas"]["RenameSecretInputBody"]["required"],
            serde_json::json!(["org_id", "new_key"])
        );
        assert_eq!(
            doc["components"]["schemas"]["SetUserSecretInputBody"]["required"],
            serde_json::json!(["key", "value"])
        );
        assert_eq!(
            doc["components"]["schemas"]["RenameUserSecretInputBody"]["properties"]["new_key"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["RenameUserSecretInputBody"]["required"],
            serde_json::json!(["new_key"])
        );
        assert_eq!(
            doc["components"]["schemas"]["SecretProject"]["properties"]["secret_count"]["type"],
            "integer"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateSecretProjectInputBody"]["properties"]["name"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["CreateSecretProjectInputBody"]["required"],
            serde_json::json!(["name"])
        );
        assert_eq!(
            doc["components"]["schemas"]["SetProjectSecretInputBody"]["properties"]["value"]["type"],
            "string"
        );
        assert_eq!(
            doc["components"]["schemas"]["SetProjectSecretInputBody"]["required"],
            serde_json::json!(["key", "value"])
        );
        assert_eq!(
            doc["components"]["schemas"]["RenameProjectSecretBody"]["required"],
            serde_json::json!(["new_key"])
        );
    }
}
