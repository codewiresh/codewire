//! CLI-owned presentation shapes retained across Connect client flips.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::organization_client::Preset;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Environment {
    pub id: String,
    pub org_id: String,
    pub created_by: String,
    pub preset_id: String,
    #[serde(rename = "type")]
    pub environment_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub isolation_tier: String,
    pub name: Option<String>,
    pub state: String,
    pub desired_state: String,
    pub error_reason: Option<String>,
    pub recoverable: bool,
    pub state_changed_at: String,
    pub retry_count: i32,
    pub ttl_seconds: Option<i32>,
    pub shutdown_at: Option<String>,
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
    pub total_running_seconds: i32,
    pub created_at: String,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub destroyed_at: Option<String>,
    pub protected: bool,
    pub deletion_requested_at: Option<String>,
    pub deletion_grace_until: Option<String>,
    pub network: Option<String>,
    pub operation_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_selection: Option<EnvironmentSourceSelection>,
}

/// Complete value-free selection, including the immutable credential revision.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSourceSelection {
    #[serde(default)]
    pub secrets: codewire_project::SecretBindings,
    #[serde(default)]
    pub credentials: Option<codewire_project::CredentialBinding>,
    #[serde(default)]
    pub profile_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateEnvironmentSourcesRequest {
    pub expected_operation_generation: u64,
    pub expected: EnvironmentSourceSelection,
    pub replacement: EnvironmentSourceSelection,
    pub allow_restart: bool,
    pub confirm_personal_credentials: bool,
    pub confirm_personal_secrets: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentSourcesUpdateOutcome {
    Unchanged,
    Stored,
    RestartRequired,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnvironmentSourcesUpdate {
    pub environment_id: String,
    pub operation_generation: u64,
    pub selection: EnvironmentSourceSelection,
    pub outcome: EnvironmentSourcesUpdateOutcome,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentResizeResources {
    pub cpu_millicores: i32,
    pub memory_mb: i32,
    pub disk_gb: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentResizeFailure {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentResizeOperation {
    pub id: String,
    pub environment_id: String,
    pub request_id: String,
    pub previous_resources: EnvironmentResizeResources,
    pub desired_resources: EnvironmentResizeResources,
    pub last_applied_resources: EnvironmentResizeResources,
    pub state: String,
    pub disruption_policy: String,
    pub planned_mode: String,
    pub applied_mode: String,
    pub pod_replaced: bool,
    pub failure: Option<EnvironmentResizeFailure>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentResizePlan {
    pub previous_resources: EnvironmentResizeResources,
    pub desired_resources: EnvironmentResizeResources,
    pub execution_mode: String,
    pub active_session_count: i32,
    pub active_sessions_will_be_terminated: bool,
    pub reason: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentResizeResult {
    pub operation: EnvironmentResizeOperation,
    pub environment: Environment,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentDaemonDiagnostic {
    pub name: String,
    pub healthy: bool,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentDaemonStatus {
    pub state: String,
    pub protocol_version: u32,
    pub minimum_protocol_version: u32,
    pub daemon_version: String,
    pub capabilities: Vec<String>,
    pub message: String,
    pub diagnostics: Vec<EnvironmentDaemonDiagnostic>,
    pub pod_name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentDaemonRepair {
    pub status: EnvironmentDaemonStatus,
    pub replaced_pod_name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentTrustReport {
    pub environment: TrustReportEnvironment,
    pub runtime: TrustReportRuntime,
    pub placement: TrustReportPlacement,
    pub images: TrustReportImages,
    pub provenance: TrustReportProvenance,
    pub attestation: TrustReportAttestation,
    pub trustee: TrustReportTrustee,
    pub summary: TrustReportSummary,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportEnvironment {
    pub id: String,
    pub org_id: String,
    #[serde(rename = "type")]
    pub environment_type: String,
    pub state: String,
    pub isolation_tier: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportRuntime {
    pub profile: String,
    pub runtime_class: String,
    pub handler: String,
    pub confidential: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportPlacement {
    pub namespace: Option<String>,
    pub workspace_pod: Option<String>,
    pub pod_ip: Option<String>,
    pub node: Option<String>,
    pub zone: Option<String>,
    pub region: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportImages {
    pub workspace_image: Option<String>,
    pub workspace_image_id: Option<String>,
    pub gateway_image: Option<String>,
    pub gateway_image_id: Option<String>,
    pub dind_image: Option<String>,
    pub dind_image_id: Option<String>,
    pub daemon_init_image: Option<String>,
    pub daemon_init_image_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportProvenance {
    pub status: String,
    pub guest_kernel: Option<String>,
    pub guest_initrd: Option<String>,
    pub guest_image: Option<String>,
    pub firmware: Option<String>,
    pub source: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportAttestation {
    pub status: String,
    pub tee: String,
    pub report_available: bool,
    pub report_source: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportTrustee {
    pub status: String,
    pub resource_uri: Option<String>,
    pub reference_values: Option<String>,
    pub policy: Option<String>,
    pub evidence_issues: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TrustReportSummary {
    pub trust_level: String,
    pub production_verified: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct CreateEnvironmentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub isolation_tier: String,
    pub project_spec: codewire_project::ProjectSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_profile_revision: Option<u64>,
    pub confirm_personal_credentials: bool,
    pub confirm_personal_secrets: bool,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PrepareEnvironmentRequest {
    #[serde(flatten)]
    pub draft: CreateEnvironmentRequest,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct PrepareEnvironmentResponse {
    pub draft: CreateEnvironmentRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_preset: Option<Preset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_config: Option<RepoConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct RepoConfig {
    pub id: String,
    pub org_id: String,
    pub repo_url: String,
    pub project_spec: codewire_project::ProjectSpec,
    pub created_by: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct StatusResponse {
    pub status: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ExtendTtlRequest {
    pub additional_seconds: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct EnvironmentAccessGrant {
    pub id: String,
    pub environment_id: String,
    pub user_id: String,
    pub permission: String,
    pub granted_by: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct GrantEnvironmentAccessRequest {
    pub user_id: String,
    pub permission: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct EnvironmentLog {
    pub id: String,
    pub environment_id: String,
    pub phase: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_request_presentation_serializes_only_canonical_project_intent() {
        let request = CreateEnvironmentRequest {
            preset_id: Some("preset_123".to_string()),
            name: Some("builder".to_string()),
            ttl_seconds: Some(3600),
            project_spec: codewire_project::ProjectSpec {
                preset: "go".to_string(),
                repositories: vec![codewire_project::RepositorySpec {
                    source: "https://github.com/codewiresh/codewire".to_string(),
                    branch: "main".to_string(),
                    destination: "/workspace/codewire".to_string(),
                    ..Default::default()
                }],
                working_directory: "/workspace/codewire".to_string(),
                environment: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
                agents: codewire_project::AgentsSpec {
                    tools: vec!["codex".to_string()],
                    ..Default::default()
                },
                resources: codewire_project::ResourceSpec {
                    cpu_millicores: Some(2000),
                    memory_mib: Some(4096),
                    disk_gib: Some(40),
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let value = serde_json::to_value(request).expect("serialize request");
        assert_eq!(value["preset_id"], "preset_123");
        assert_eq!(value["name"], "builder");
        assert_eq!(value["project_spec"]["resources"]["cpu_millicores"], 2000);
        assert_eq!(value["project_spec"]["repositories"][0]["branch"], "main");
        assert_eq!(
            value["project_spec"]["repositories"][0]["destination"],
            "/workspace/codewire"
        );
        assert_eq!(value["project_spec"]["environment"]["FOO"], "bar");
        assert_eq!(value["project_spec"]["agents"]["tools"][0], "codex");
        for removed in ["image", "repos", "env_vars", "agents", "agent_env"] {
            assert!(
                value.get(removed).is_none(),
                "unexpected top-level {removed}"
            );
        }

        let empty = serde_json::to_value(CreateEnvironmentRequest::default()).unwrap();
        assert!(empty.get("project_spec").is_some());
    }

    #[test]
    fn environment_resize_result_keeps_operation_and_environment_shape() {
        let result = EnvironmentResizeResult {
            operation: EnvironmentResizeOperation {
                id: "resize_1".to_string(),
                environment_id: "env_1".to_string(),
                request_id: "request_1".to_string(),
                previous_resources: EnvironmentResizeResources {
                    cpu_millicores: 2000,
                    memory_mb: 4096,
                    disk_gb: 20,
                },
                desired_resources: EnvironmentResizeResources {
                    cpu_millicores: 3000,
                    memory_mb: 6144,
                    disk_gb: 30,
                },
                last_applied_resources: EnvironmentResizeResources {
                    cpu_millicores: 3000,
                    memory_mb: 6144,
                    disk_gb: 30,
                },
                state: "completed".to_string(),
                disruption_policy: "allow_restart".to_string(),
                planned_mode: "restart".to_string(),
                applied_mode: "restart".to_string(),
                pod_replaced: true,
                created_at: "2026-08-02T00:00:00Z".to_string(),
                updated_at: "2026-08-02T00:01:00Z".to_string(),
                completed_at: Some("2026-08-02T00:01:00Z".to_string()),
                ..Default::default()
            },
            environment: Environment {
                id: "env_1".to_string(),
                cpu_millicores: 3000,
                memory_mb: 6144,
                disk_gb: 30,
                ..Default::default()
            },
        };

        let value = serde_json::to_value(result).expect("serialize resize result");
        assert_eq!(value["operation"]["request_id"], "request_1");
        assert_eq!(value["operation"]["state"], "completed");
        assert_eq!(value["operation"]["disruption_policy"], "allow_restart");
        assert_eq!(value["operation"]["planned_mode"], "restart");
        assert_eq!(value["operation"]["applied_mode"], "restart");
        assert_eq!(value["operation"]["pod_replaced"], true);
        assert_eq!(value["operation"]["last_applied_resources"]["disk_gb"], 30);
        assert_eq!(value["environment"]["cpu_millicores"], 3000);
    }
}
