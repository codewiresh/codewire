use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message as _;
use codewire_proto::google::rpc::{BadRequest, ErrorInfo};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AuthQuery {
    #[serde(default, rename = "authRequestID")]
    pub(crate) auth_request_id: String,
    #[serde(default)]
    pub(crate) return_to: String,
    #[serde(default)]
    pub(crate) token: String,
    #[serde(default)]
    pub(crate) user_code: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthFormSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    #[serde(default)]
    pub(crate) email: String,
    #[serde(default)]
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) confirm_password: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) invite_code: String,
    #[serde(default)]
    pub(crate) code: String,
    #[serde(default, rename = "authRequestID")]
    pub(crate) auth_request_id: String,
    #[serde(default)]
    pub(crate) return_to: String,
}

#[derive(Debug)]
pub(crate) struct AuthFormView {
    pub(crate) title: &'static str,
    pub(crate) description: &'static str,
    pub(crate) action: &'static str,
    pub(crate) submit_label: &'static str,
    pub(crate) error: String,
    pub(crate) csrf_token: String,
    pub(crate) auth_request_id: String,
    pub(crate) return_to: String,
    pub(crate) show_email: bool,
    pub(crate) show_password: bool,
    pub(crate) new_password: bool,
    pub(crate) show_confirm_password: bool,
    pub(crate) show_name: bool,
    pub(crate) show_invite_code: bool,
    pub(crate) show_totp_code: bool,
    pub(crate) forgot_password_link: bool,
    pub(crate) secondary_label: &'static str,
    pub(crate) secondary_url: String,
}

#[derive(Debug)]
pub(crate) struct SetupTwoFactorView {
    pub(crate) csrf_token: String,
    pub(crate) return_to: String,
    pub(crate) qr_svg: String,
    pub(crate) secret: String,
    pub(crate) error: String,
}

#[derive(Debug)]
pub(crate) struct TwoFactorRecoveryView {
    pub(crate) return_to: String,
    pub(crate) backup_codes: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct DevicePageView {
    pub(crate) user_code: String,
    pub(crate) csrf_token: String,
    pub(crate) error: String,
    pub(crate) approved: bool,
}

#[derive(Debug)]
pub(crate) struct InvitationView {
    pub(crate) organization_name: String,
    pub(crate) email: String,
    pub(crate) inviter_name: String,
    pub(crate) role: &'static str,
}

#[derive(Debug)]
pub(crate) struct InvitationPageView {
    pub(crate) invitation: InvitationView,
    pub(crate) token: String,
    pub(crate) csrf_token: String,
    pub(crate) authenticated: bool,
    pub(crate) email_matches: bool,
    pub(crate) login_url: String,
    pub(crate) signup_url: String,
    pub(crate) error: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CsrfSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) user_code: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InvitationSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitCredentialSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) name: String,
    pub(crate) host: String,
    #[serde(default)]
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CredentialIdSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) credential_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitIdentitySubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) git_name: String,
    pub(crate) git_email: String,
}

#[derive(Debug)]
pub(crate) struct GitCredentialRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) username: String,
}

#[derive(Debug, Default)]
pub(crate) struct SettingsData {
    pub(crate) github_available: bool,
    pub(crate) github_connected: bool,
    pub(crate) github_username: String,
    pub(crate) credentials_available: bool,
    pub(crate) credentials: Vec<GitCredentialRow>,
    pub(crate) git_identity_available: bool,
    pub(crate) git_name: String,
    pub(crate) git_email: String,
    pub(crate) ssh_key_status_available: bool,
    pub(crate) ssh_key_available: bool,
    pub(crate) ssh_public_key: String,
    pub(crate) ssh_fingerprint: String,
}

#[derive(Debug)]
pub(crate) struct SettingsPageView {
    pub(crate) data: SettingsData,
    pub(crate) csrf_token: String,
    pub(crate) github_connect_url: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Debug)]
pub(crate) struct SettingsPlaceholderView {
    pub(crate) section: &'static str,
    pub(crate) title: &'static str,
    pub(crate) heading: &'static str,
    pub(crate) description: &'static str,
}

#[derive(Debug)]
pub(crate) struct DashboardView {
    pub(crate) user_name: String,
    pub(crate) is_admin: bool,
    pub(crate) organizations: Vec<OrganizationRow>,
    pub(crate) has_organizations: bool,
    pub(crate) github_connected: bool,
    pub(crate) github_available: bool,
    pub(crate) show_checklist: bool,
    pub(crate) new_organization_url: String,
    pub(crate) settings_url: String,
    pub(crate) global_context_query: String,
    pub(crate) github_connect_url: String,
    pub(crate) has_selected_organization: bool,
    pub(crate) selected_organization_name: String,
    pub(crate) selected_organization_slug: String,
    pub(crate) selected_organization_url: String,
    pub(crate) sandboxes: Vec<EnvironmentRow>,
    pub(crate) recent_sandboxes: Vec<EnvironmentRow>,
    pub(crate) sandbox_rail_available: bool,
    pub(crate) sandbox_total: usize,
    pub(crate) sandbox_running: usize,
    pub(crate) sandbox_stopped: usize,
    pub(crate) sandbox_attention: usize,
    pub(crate) provisioned_cpu_millicores: i64,
    pub(crate) provisioned_memory_mb: i64,
    pub(crate) provisioned_disk_gb: i64,
}

impl DashboardView {
    pub(crate) fn select_organization(
        &mut self,
        organization: &OrganizationContext,
        sandboxes: Vec<EnvironmentRow>,
        rail_available: bool,
    ) {
        self.has_selected_organization = true;
        self.selected_organization_name = organization.name.clone();
        self.selected_organization_slug = organization.slug.clone();
        self.selected_organization_url = organization.environments_url.clone();
        self.global_context_query = format!("?org={}", organization.slug);
        self.settings_url = format!("/settings/{}", self.global_context_query);
        self.sandbox_total = sandboxes.len();
        self.sandbox_running = sandboxes
            .iter()
            .filter(|sandbox| sandbox.state == "running")
            .count();
        self.sandbox_stopped = sandboxes
            .iter()
            .filter(|sandbox| sandbox.state == "stopped")
            .count();
        self.sandbox_attention = sandboxes
            .iter()
            .filter(|sandbox| sandbox.state == "error")
            .count();
        self.provisioned_cpu_millicores = sandboxes
            .iter()
            .map(|sandbox| i64::from(sandbox.cpu_millicores))
            .sum();
        self.provisioned_memory_mb = sandboxes
            .iter()
            .map(|sandbox| i64::from(sandbox.memory_mb))
            .sum();
        self.provisioned_disk_gb = sandboxes
            .iter()
            .map(|sandbox| i64::from(sandbox.disk_gb))
            .sum();
        self.recent_sandboxes = sandboxes.iter().take(5).cloned().collect();
        self.sandboxes = sandboxes;
        self.sandbox_rail_available = rail_available;
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OrganizationRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) role: &'static str,
    pub(crate) can_admin: bool,
    pub(crate) billing_plan: String,
    pub(crate) url: String,
}

#[derive(Debug)]
pub(crate) struct OrganizationContext {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) role: &'static str,
    pub(crate) can_admin: bool,
    pub(crate) environments_url: String,
    pub(crate) snapshots_url: String,
    pub(crate) presets_url: String,
    pub(crate) secrets_url: String,
    pub(crate) api_keys_url: String,
    pub(crate) members_url: String,
    pub(crate) billing_url: String,
}

impl OrganizationContext {
    pub(crate) fn from_row(row: &OrganizationRow) -> Self {
        let local_base = format!("/{}", row.slug);
        Self {
            id: row.id.clone(),
            name: row.name.clone(),
            slug: row.slug.clone(),
            role: row.role,
            can_admin: row.can_admin,
            environments_url: format!("{local_base}/"),
            snapshots_url: format!("{local_base}/snapshots/"),
            presets_url: format!("{local_base}/presets/"),
            secrets_url: format!("{local_base}/secrets/"),
            api_keys_url: format!("{local_base}/api-keys/"),
            members_url: format!("{local_base}/members/"),
            billing_url: format!("{local_base}/billing/"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentPortRow {
    pub(crate) id: String,
    pub(crate) port: i32,
    pub(crate) label: String,
    pub(crate) access: &'static str,
    pub(crate) preview_url: String,
    pub(crate) has_preview: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) state: &'static str,
    pub(crate) state_tone: &'static str,
    pub(crate) state_symbol: &'static str,
    pub(crate) preset_name: String,
    pub(crate) isolation_tier: &'static str,
    pub(crate) last_event: String,
    pub(crate) created: String,
    pub(crate) cost: String,
    pub(crate) running_time: String,
    pub(crate) resources: String,
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mb: i32,
    pub(crate) disk_gb: i32,
    pub(crate) hourly_rate: String,
    pub(crate) can_start: bool,
    pub(crate) can_stop: bool,
    pub(crate) can_destroy: bool,
    pub(crate) confidential_actions_allowed: bool,
    pub(crate) vscode_url: String,
    pub(crate) ports: Vec<EnvironmentPortRow>,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentResizeConfirmationView {
    pub(crate) environment_id: String,
    pub(crate) environment_name: String,
    pub(crate) request_id: String,
    pub(crate) previous_resources: String,
    pub(crate) desired_resources: String,
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mb: i32,
    pub(crate) disk_gb: i32,
    pub(crate) execution_mode: &'static str,
    pub(crate) requires_restart: bool,
    pub(crate) active_session_count: i32,
    pub(crate) active_sessions_will_be_terminated: bool,
    pub(crate) reason: String,
    pub(crate) warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentResizeOperationView {
    pub(crate) environment_id: String,
    pub(crate) operation_id: String,
    pub(crate) state: &'static str,
    pub(crate) desired_resources: String,
    pub(crate) applied_resources: String,
    pub(crate) failure: String,
    pub(crate) active: bool,
    pub(crate) pod_replaced: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct TerminalPageView {
    pub(crate) organization_id: String,
    pub(crate) environment: EnvironmentRow,
    pub(crate) websocket_origin: String,
}

#[derive(Clone, Debug)]
pub(crate) struct GitHubRepositoryOption {
    pub(crate) full_name: String,
    pub(crate) url: String,
    pub(crate) description: String,
    pub(crate) language: String,
    pub(crate) private: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentPresetOption {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) image: String,
    pub(crate) default_cpu_millicores: i32,
    pub(crate) default_memory_mb: i32,
    pub(crate) default_disk_gb: i32,
    pub(crate) default_ttl_seconds: Option<i32>,
    pub(crate) default_install_command: String,
    pub(crate) default_startup_script: String,
    pub(crate) default_agents: Vec<String>,
    pub(crate) default_app_ports: Vec<EnvironmentAppPortFormRow>,
    pub(crate) default_include_org_secrets: bool,
    pub(crate) default_include_user_secrets: bool,
    pub(crate) secret_project: String,
    pub(crate) official: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentSecretProjectOption {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) secret_count: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentRepositoryFormRow {
    pub(crate) index: usize,
    pub(crate) url: String,
    pub(crate) branch: String,
    pub(crate) mount_path: String,
}

impl EnvironmentRepositoryFormRow {
    pub(crate) fn mount_suffix(&self) -> &str {
        workspace_mount_suffix(&self.mount_path)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentAppPortFormRow {
    pub(crate) index: usize,
    pub(crate) port: String,
    pub(crate) label: String,
    pub(crate) access: String,
}

impl EnvironmentAppPortFormRow {
    pub(crate) fn access_selected(&self, value: &str) -> bool {
        self.access == value
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentAgentSecretView {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) placeholder: &'static str,
    pub(crate) configured: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentAgentView {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
    pub(crate) secrets: Vec<EnvironmentAgentSecretView>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EnvironmentDetectionView {
    pub(crate) project_type: String,
    pub(crate) language: String,
    pub(crate) framework: String,
    pub(crate) image: String,
    pub(crate) setup_notes: String,
    pub(crate) needs_docker: bool,
    pub(crate) has_compose: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentCreateFormView {
    pub(crate) csrf_token: String,
    pub(crate) expanded: bool,
    pub(crate) prepared: bool,
    pub(crate) mode: String,
    pub(crate) name: String,
    pub(crate) preset_id: String,
    pub(crate) image: String,
    pub(crate) repositories: Vec<EnvironmentRepositoryFormRow>,
    pub(crate) install_command: String,
    pub(crate) startup_script: String,
    pub(crate) cpu: String,
    pub(crate) memory: String,
    pub(crate) disk: String,
    pub(crate) ttl: String,
    pub(crate) isolation_tier: String,
    pub(crate) confidential_available: bool,
    pub(crate) show_confidential_controls: bool,
    pub(crate) confidential_price: String,
    pub(crate) selected_agents: Vec<String>,
    pub(crate) secret_project: String,
    pub(crate) include_org_secrets: bool,
    pub(crate) include_user_secrets: bool,
    pub(crate) app_ports: Vec<EnvironmentAppPortFormRow>,
    pub(crate) github_connected: bool,
    pub(crate) github_username: String,
    pub(crate) github_repositories_available: bool,
    pub(crate) github_repositories: Vec<GitHubRepositoryOption>,
    pub(crate) presets: Vec<EnvironmentPresetOption>,
    pub(crate) secret_projects: Vec<EnvironmentSecretProjectOption>,
    pub(crate) agents: Vec<EnvironmentAgentView>,
    pub(crate) detection: EnvironmentDetectionView,
    pub(crate) repo_error: String,
    pub(crate) image_error: String,
    pub(crate) name_error: String,
    pub(crate) cpu_error: String,
    pub(crate) memory_error: String,
    pub(crate) disk_error: String,
    pub(crate) ttl_error: String,
    pub(crate) form_error: String,
}

impl EnvironmentCreateFormView {
    pub(crate) fn isolation_selected(&self, value: &str) -> bool {
        self.isolation_tier == value
    }

    pub(crate) fn repository_selected(&self, value: &str) -> bool {
        self.repositories
            .iter()
            .any(|repository| repository.url == value)
    }

    pub(crate) fn has_repository(&self) -> bool {
        self.repositories
            .iter()
            .any(|repository| !repository.url.trim().is_empty())
    }

    pub(crate) fn has_selected_github_repository(&self) -> bool {
        self.github_repositories
            .iter()
            .any(|repository| self.repository_selected(&repository.url))
    }

    pub(crate) fn repository_mount_suffix(&self, value: &str) -> &str {
        self.repositories
            .iter()
            .find(|repository| repository.url == value)
            .map_or("", |repository| repository.mount_suffix())
    }

    pub(crate) fn secret_project_selected(&self, value: &str) -> bool {
        self.secret_project == value
    }

    pub(crate) fn agent_selected(&self, value: &str) -> bool {
        self.selected_agents.iter().any(|agent| agent == value)
    }

    pub(crate) fn has_errors(&self) -> bool {
        !self.repo_error.is_empty()
            || !self.image_error.is_empty()
            || !self.name_error.is_empty()
            || !self.cpu_error.is_empty()
            || !self.memory_error.is_empty()
            || !self.disk_error.is_empty()
            || !self.ttl_error.is_empty()
            || !self.form_error.is_empty()
    }
}

fn workspace_mount_suffix(value: &str) -> &str {
    if value == "/workspace" {
        ""
    } else {
        value
            .strip_prefix("/workspace/")
            .or_else(|| value.strip_prefix('/'))
            .unwrap_or(value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentPortPanelView {
    pub(crate) environment_id: String,
    pub(crate) environment_name: String,
    pub(crate) ports: Vec<EnvironmentPortRow>,
    pub(crate) port: String,
    pub(crate) label: String,
    pub(crate) access: String,
    pub(crate) form_error: String,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentTrustSummaryView {
    pub(crate) environment_name: String,
    pub(crate) trust_level: String,
    pub(crate) production_verified: bool,
    pub(crate) attestation_status: String,
    pub(crate) tee: String,
    pub(crate) warnings: Vec<String>,
}

impl EnvironmentPortPanelView {
    pub(crate) fn access_selected(&self, value: &str) -> bool {
        self.access == value
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentsPageView {
    pub(crate) environments: Vec<EnvironmentRow>,
    pub(crate) create_form: EnvironmentCreateFormView,
    pub(crate) port_panel: Option<EnvironmentPortPanelView>,
    pub(crate) trust_summary: Option<EnvironmentTrustSummaryView>,
    pub(crate) resize_confirmation: Option<EnvironmentResizeConfirmationView>,
    pub(crate) resize_operation: Option<EnvironmentResizeOperationView>,
    pub(crate) search: String,
    pub(crate) state: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

impl EnvironmentsPageView {
    pub(crate) fn state_selected(&self, value: &str) -> bool {
        self.state == value
    }
}

#[derive(Debug)]
pub(crate) struct MemberRow {
    pub(crate) id: String,
    pub(crate) user_id: String,
    pub(crate) display_name: String,
    pub(crate) email: String,
    pub(crate) initial: char,
    pub(crate) role: &'static str,
    pub(crate) is_owner: bool,
    pub(crate) assignments: Vec<AssignmentView>,
    pub(crate) selected_assignments: Vec<String>,
}

impl MemberRow {
    pub(crate) fn assignment_selected(&self, value: &str) -> bool {
        self.selected_assignments.iter().any(|item| item == value)
    }
}

#[derive(Debug)]
pub(crate) struct InvitationRow {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) inviter_name: String,
    pub(crate) role: &'static str,
    pub(crate) expires: String,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AssignmentView {
    pub(crate) value: &'static str,
    pub(crate) label: &'static str,
    pub(crate) tone: &'static str,
}

pub(crate) const ASSIGNMENTS: [AssignmentView; 7] = [
    AssignmentView {
        value: "viewer",
        label: "Viewer",
        tone: "neutral",
    },
    AssignmentView {
        value: "developer",
        label: "Developer",
        tone: "info",
    },
    AssignmentView {
        value: "environments_admin",
        label: "Sandboxes Admin",
        tone: "success",
    },
    AssignmentView {
        value: "sandboxes_admin",
        label: "Sandboxes Admin",
        tone: "purple",
    },
    AssignmentView {
        value: "billing_admin",
        label: "Billing Admin",
        tone: "warning",
    },
    AssignmentView {
        value: "auditor",
        label: "Auditor",
        tone: "orange",
    },
    AssignmentView {
        value: "super_admin",
        label: "Super Admin",
        tone: "danger",
    },
];

#[derive(Debug, Default)]
pub(crate) struct InviteFormView {
    pub(crate) email: String,
    pub(crate) role: String,
    pub(crate) assignments: Vec<String>,
    pub(crate) email_error: String,
    pub(crate) role_error: String,
    pub(crate) form_error: String,
    pub(crate) expanded: bool,
}

impl InviteFormView {
    pub(crate) fn assignment_selected(&self, value: &str) -> bool {
        value == "viewer" || self.assignments.iter().any(|item| item == value)
    }

    pub(crate) fn has_errors(&self) -> bool {
        !self.email_error.is_empty() || !self.role_error.is_empty() || !self.form_error.is_empty()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct InviteSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) email: String,
    pub(crate) role: String,
    #[serde(default)]
    pub(crate) developer: Option<String>,
    #[serde(default)]
    pub(crate) environments_admin: Option<String>,
    #[serde(default)]
    pub(crate) sandboxes_admin: Option<String>,
    #[serde(default)]
    pub(crate) billing_admin: Option<String>,
    #[serde(default)]
    pub(crate) auditor: Option<String>,
    #[serde(default)]
    pub(crate) super_admin: Option<String>,
}

impl InviteSubmission {
    pub(crate) fn assignments(&self) -> Vec<String> {
        let mut selected = vec!["viewer".to_owned()];
        for (value, present) in [
            ("developer", &self.developer),
            ("environments_admin", &self.environments_admin),
            ("sandboxes_admin", &self.sandboxes_admin),
            ("billing_admin", &self.billing_admin),
            ("auditor", &self.auditor),
            ("super_admin", &self.super_admin),
        ] {
            if present.is_some() {
                selected.push(value.to_owned());
            }
        }
        selected
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct MemberRoleSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) user_id: String,
    pub(crate) role: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MemberIdSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) member_id: String,
    #[serde(default)]
    pub(crate) developer: Option<String>,
    #[serde(default)]
    pub(crate) environments_admin: Option<String>,
    #[serde(default)]
    pub(crate) sandboxes_admin: Option<String>,
    #[serde(default)]
    pub(crate) billing_admin: Option<String>,
    #[serde(default)]
    pub(crate) auditor: Option<String>,
    #[serde(default)]
    pub(crate) super_admin: Option<String>,
}

impl MemberIdSubmission {
    pub(crate) fn assignments(&self) -> Vec<String> {
        let mut selected = vec!["viewer".to_owned()];
        for (value, present) in [
            ("developer", &self.developer),
            ("environments_admin", &self.environments_admin),
            ("sandboxes_admin", &self.sandboxes_admin),
            ("billing_admin", &self.billing_admin),
            ("auditor", &self.auditor),
            ("super_admin", &self.super_admin),
        ] {
            if present.is_some() {
                selected.push(value.to_owned());
            }
        }
        selected
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoveMemberSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) user_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InvitationIdSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) invitation_id: String,
}

pub(crate) struct MembersPageView {
    pub(crate) members: Vec<MemberRow>,
    pub(crate) invitations: Vec<InvitationRow>,
    pub(crate) assignment_options: &'static [AssignmentView],
    pub(crate) invite_form: InviteFormView,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Debug)]
pub(crate) struct ApiKeyRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) prefix: String,
    pub(crate) created_by: String,
    pub(crate) created: String,
    pub(crate) last_used: String,
    pub(crate) status: &'static str,
    pub(crate) status_tone: &'static str,
    pub(crate) disabled: bool,
    pub(crate) expired: bool,
}

#[derive(Debug, Default)]
pub(crate) struct ApiKeyFormView {
    pub(crate) name: String,
    pub(crate) expiration: String,
    pub(crate) name_error: String,
    pub(crate) expiration_error: String,
    pub(crate) form_error: String,
    pub(crate) expanded: bool,
}

impl ApiKeyFormView {
    pub(crate) fn has_errors(&self) -> bool {
        !self.name_error.is_empty()
            || !self.expiration_error.is_empty()
            || !self.form_error.is_empty()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiKeyCreateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) name: String,
    pub(crate) expiration: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiKeyToggleSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) key_id: String,
    pub(crate) disabled: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiKeyIdSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) key_id: String,
}

// Deliberately not Debug: this is the only presentation model allowed to own
// one-time API-key material, and derived diagnostics must never expose it.
pub(crate) struct ApiKeysPageView {
    pub(crate) keys: Vec<ApiKeyRow>,
    pub(crate) form: ApiKeyFormView,
    pub(crate) csrf_token: String,
    pub(crate) one_time_key: String,
    pub(crate) has_one_time_key: bool,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Debug)]
pub(crate) struct SecretProjectRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) secret_count: i64,
    pub(crate) created: String,
}

#[derive(Debug)]
pub(crate) struct SecretRow {
    pub(crate) key: String,
    pub(crate) updated: String,
}

#[derive(Debug, Default)]
pub(crate) struct SecretProjectFormView {
    pub(crate) name: String,
    pub(crate) name_error: String,
    pub(crate) form_error: String,
    pub(crate) expanded: bool,
}

#[derive(Debug)]
pub(crate) struct SecretProjectsPageView {
    pub(crate) projects: Vec<SecretProjectRow>,
    pub(crate) form: SecretProjectFormView,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

// Deliberately has no secret-value field. The renderer can preserve a
// non-sensitive key after validation, but every response renders the value
// input blank so secret material cannot enter retained HTML.
#[derive(Debug, Default)]
pub(crate) struct SecretFormView {
    pub(crate) key: String,
    pub(crate) key_error: String,
    pub(crate) form_error: String,
    pub(crate) expanded: bool,
}

#[derive(Debug)]
pub(crate) struct SecretBucketPageView {
    pub(crate) title: String,
    pub(crate) description: &'static str,
    pub(crate) bucket: String,
    pub(crate) secrets: Vec<SecretRow>,
    pub(crate) can_manage: bool,
    pub(crate) form: SecretFormView,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Deserialize)]
pub(crate) struct SecretSetSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretKeySubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretRenameSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) key: String,
    pub(crate) new_key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretProjectCreateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SecretProjectDeleteSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) project_id: String,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PresetFormView {
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) description: String,
    pub(crate) image: String,
    pub(crate) cpu: String,
    pub(crate) memory: String,
    pub(crate) disk: String,
    pub(crate) ttl: String,
    pub(crate) install_command: String,
    pub(crate) startup_script: String,
    pub(crate) name_error: String,
    pub(crate) cpu_error: String,
    pub(crate) memory_error: String,
    pub(crate) disk_error: String,
    pub(crate) ttl_error: String,
    pub(crate) form_error: String,
    pub(crate) expanded: bool,
}

#[derive(Debug)]
pub(crate) struct PresetRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) description: String,
    pub(crate) image: String,
    pub(crate) cpu: String,
    pub(crate) memory: String,
    pub(crate) disk: String,
    pub(crate) ttl: String,
    pub(crate) official: bool,
    pub(crate) organization_owned: bool,
    pub(crate) form: PresetFormView,
}

#[derive(Debug)]
pub(crate) struct PresetsPageView {
    pub(crate) presets: Vec<PresetRow>,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Deserialize)]
pub(crate) struct PresetUpdateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) preset_id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) slug: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) image: String,
    pub(crate) cpu: String,
    pub(crate) memory: String,
    pub(crate) disk: String,
    #[serde(default)]
    pub(crate) ttl: String,
    #[serde(default)]
    pub(crate) install_command: String,
    #[serde(default)]
    pub(crate) startup_script: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PresetDeleteSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) preset_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OrganizationFormSubmission {
    pub(crate) name: String,
    pub(crate) slug: String,
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
}

#[derive(Debug, Default)]
pub(crate) struct OrganizationFormView {
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) name_error: String,
    pub(crate) slug_error: String,
    pub(crate) form_error: String,
}

impl OrganizationFormView {
    pub(crate) fn has_errors(&self) -> bool {
        !self.name_error.is_empty() || !self.slug_error.is_empty() || !self.form_error.is_empty()
    }
}

pub(crate) fn validate_organization_form(form: &mut OrganizationFormView) {
    if form.name.is_empty() {
        form.name_error = "Name is required".to_owned();
    }
    if form.slug.len() < 3 || form.slug.len() > 48 {
        form.slug_error = "Slug must be between 3 and 48 characters".to_owned();
    } else if !valid_organization_slug(&form.slug) {
        form.slug_error =
            "Slug is reserved or must contain only lowercase letters, numbers, and single hyphens"
                .to_owned();
    }
}

pub(crate) fn valid_organization_slug(slug: &str) -> bool {
    codewire_server_core::organization_slug::valid_organization_slug(slug)
}

pub(crate) fn apply_organization_error(form: &mut OrganizationFormView, error: &ConnectError) {
    for (field, description) in bad_request_fields(error) {
        match field.trim_start_matches('/') {
            "name" => form.name_error = description,
            "slug" => form.slug_error = description,
            _ => {}
        }
    }
    if matches!(error.code, ErrorCode::AlreadyExists | ErrorCode::Aborted) {
        form.slug_error = "An organization with this slug already exists".to_owned();
    }
    if form.name_error.is_empty() && form.slug_error.is_empty() {
        form.form_error = "The organization could not be created. Please try again.".to_owned();
    }
}

pub(crate) fn bad_request_fields(error: &ConnectError) -> Vec<(String, String)> {
    error
        .details
        .iter()
        .filter(|detail| {
            detail.type_url == "google.rpc.BadRequest"
                || detail.type_url.rsplit('/').next() == Some("google.rpc.BadRequest")
        })
        .filter_map(|detail| detail.value.as_deref())
        .filter_map(|encoded| {
            STANDARD_NO_PAD
                .decode(encoded)
                .or_else(|_| STANDARD.decode(encoded))
                .ok()
        })
        .filter_map(|bytes| BadRequest::decode_from_slice(&bytes).ok())
        .flat_map(|detail| detail.field_violations)
        .map(|violation| (violation.field, violation.description))
        .collect()
}

pub(crate) fn connect_error_reason(error: &ConnectError) -> Option<String> {
    error
        .details
        .iter()
        .find(|detail| {
            detail.type_url == "google.rpc.ErrorInfo"
                || detail.type_url.rsplit('/').next() == Some("google.rpc.ErrorInfo")
        })
        .and_then(|detail| detail.value.as_deref())
        .and_then(|encoded| {
            STANDARD_NO_PAD
                .decode(encoded)
                .or_else(|_| STANDARD.decode(encoded))
                .ok()
        })
        .and_then(|bytes| ErrorInfo::decode_from_slice(&bytes).ok())
        .map(|detail| detail.reason)
        .filter(|reason| !reason.is_empty())
}
