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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Why a stopped environment was stopped: user, credit or idle (#3384).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// Seconds with no activity before a cloud sandbox stops; 0 never does.
    #[serde(default)]
    pub idle_stop_seconds: i32,
    /// Whether the server stops idle environments; when false the timeout
    /// is kept but nothing stops for being idle. `None` from a server older
    /// than the field, which says nothing either way (#3384).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_stop_enforced: Option<bool>,
    /// When a running Sandbox was running again after a restart nobody
    /// asked for, RFC 3339 (#5997); cleared by the next start or stop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restarted_at: Option<String>,
    /// Why, with `restarted_at`: `pod_failed`, `runtime_replaced`,
    /// `node_lost` or `configuration_changed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_cause: Option<String>,
    pub recoverable: bool,
    pub state_changed_at: String,
    pub retry_count: i32,
    pub setup_phase: i32,
    pub setup_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_error: Option<String>,
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
    /// `pending`, `attached`, `failed` or `revoked` while `network` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_state: Option<String>,
    /// Why joining `network` failed, with `network_state` `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_failure: Option<String>,
    /// What enforces a hosted environment's egress (#4000): `not_enforced`,
    /// `enforced`, `enforcing` or `failed_closed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_enforcement: Option<String>,
    /// Why egress failed closed, with `egress_enforcement` `failed_closed`
    /// (#5068): `self_check_failed`, `policy_digest_mismatch` or
    /// `lockdown_not_applied`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_failure: Option<String>,
    pub operation_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_selection: Option<EnvironmentSourceSelection>,
    /// The network policy a hosted environment selects, and whether it is
    /// enforced; unset where the deployment has no organization network
    /// policies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<EnvironmentNetworkPolicy>,
}

/// A hosted environment's network policy (#4000).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct EnvironmentNetworkPolicy {
    /// `open`, `web`, `locked` or `platform:id:UUID`; empty when the
    /// environment selects nothing and is on `open` by default.
    pub reference: String,
    pub name: String,
    /// The selected policy's current revision; zero for a built-in.
    pub revision: u32,
    /// `not_enforced` (the deployment's hosted egress is off), `unconfirmed`
    /// (it is on, but no fresh report confirms the policy), `enforced`,
    /// `enforcing`, `failed_closed` or `unknown`.
    pub enforcement: String,
    /// The revision cw-egress enforces, once it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforced_revision: Option<u32>,
}

impl EnvironmentNetworkPolicy {
    /// Whether this is the selection `asked` names: a built-in, a stored
    /// policy's name, `platform:NAME` or its `platform:id:` reference.
    pub fn selects(&self, asked: &str) -> bool {
        asked == self.reference
            || asked == self.name
            || asked.strip_prefix("platform:") == Some(self.name.as_str())
    }

    /// `web · rev 2 · not enforced`: the policy and its state, in words.
    pub fn summary(&self) -> String {
        let revision = match self.revision {
            0 => String::new(),
            revision => format!(" · rev {revision}"),
        };
        let state = match self.enforcement.as_str() {
            "enforced" => match self.enforced_revision {
                Some(enforced) => format!("enforces rev {enforced}"),
                None => "enforced".to_owned(),
            },
            "enforcing" => "applying the new revision".to_owned(),
            "failed_closed" => "no egress: enforcement failed".to_owned(),
            "not_enforced" => "not enforced".to_owned(),
            "unconfirmed" => "unconfirmed".to_owned(),
            _ => "enforcement unknown".to_owned(),
        };
        // An environment that selects nothing is on its default (#3997).
        let default = if self.reference.is_empty() && !self.name.is_empty() {
            " (default)"
        } else {
            ""
        };
        format!("{}{default}{revision} · {state}", self.name)
    }
}

/// How long the platform lists a create it ended, matching the server's
/// `FAILED_CREATE_LISTED_HOURS`.
const FAILED_CREATE_LISTED_HOURS: i64 = 24;

impl Environment {
    /// A create the platform ended within the last day: no capacity, or a
    /// container that could not start. The platform destroyed it at once, and
    /// the row stays listed for a day so that its user can see why (#4482).
    pub fn failed_create(&self) -> bool {
        self.failed_create_at(chrono::Utc::now())
    }

    /// [`Self::failed_create`] at a given time. The rule is the server's: an
    /// older one, or one that ever ran, is an ordinary destroyed environment.
    pub fn failed_create_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.state == "destroyed"
            && self.started_at.is_none()
            && self.stopped_at.is_none()
            && matches!(
                self.error_code.as_deref(),
                Some("no_capacity" | "container_start_failed")
            )
            && chrono::DateTime::parse_from_rfc3339(self.failed_create_time()).is_ok_and(|at| {
                now.signed_duration_since(at).num_hours() < FAILED_CREATE_LISTED_HOURS
            })
    }

    /// When the platform removed a failed create.
    pub fn failed_create_time(&self) -> &str {
        self.destroyed_at
            .as_deref()
            .unwrap_or(&self.state_changed_at)
    }
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
    /// Seconds with no activity before the sandbox stops, 0 for off; `None`
    /// takes the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_stop_seconds: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub isolation_tier: String,
    pub project_spec: codewire_project::ProjectSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_profile_revision: Option<u64>,
    pub confirm_personal_credentials: bool,
    pub confirm_personal_secrets: bool,
    pub omit_application_previews: bool,
    /// The hosted Mesh network to join, by name, in the organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// The network policy to select: a reference such as `platform:team`,
    /// `locked` or `open` (#4000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<String>,
    /// The hosted disk snapshot to start from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_snapshot_id: Option<String>,
    /// The enrolled host to run on, by name or ID (#3609).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement_host: Option<String>,
    /// This create's request ID, so a retry returns its environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
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

/// One `environment_logs` row; the client core owns its shape (#3825).
pub use codewire_client::environment_setup::EnvironmentLogRow as EnvironmentLog;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_network_policy_summary_says_whether_it_is_enforced() {
        let policy = |name: &str, revision, enforcement: &str, enforced| EnvironmentNetworkPolicy {
            reference: name.into(),
            name: name.into(),
            revision,
            enforcement: enforcement.into(),
            enforced_revision: enforced,
        };
        assert_eq!(
            policy("web", 2, "not_enforced", None).summary(),
            "web · rev 2 · not enforced"
        );
        assert_eq!(
            policy("open", 0, "not_enforced", None).summary(),
            "open · not enforced"
        );
        let unselected = EnvironmentNetworkPolicy {
            reference: String::new(),
            ..policy("open", 0, "not_enforced", None)
        };
        assert_eq!(unselected.summary(), "open (default) · not enforced");
        assert_eq!(
            policy("web", 0, "unconfirmed", None).summary(),
            "web · unconfirmed"
        );
        assert_eq!(
            policy("web", 3, "enforced", Some(3)).summary(),
            "web · rev 3 · enforces rev 3"
        );
        assert_eq!(
            policy("web", 3, "enforcing", Some(2)).summary(),
            "web · rev 3 · applying the new revision"
        );
        assert_eq!(
            policy("web", 3, "failed_closed", None).summary(),
            "web · rev 3 · no egress: enforcement failed"
        );
    }

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
