use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message as _;
use codewire_proto::google::rpc::{BadRequest, ErrorInfo};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;
use std::fmt;

#[derive(Default, Deserialize)]
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

impl fmt::Debug for AuthQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthQuery")
            .field("auth_request_id", &redacted(&self.auth_request_id))
            .field("return_to", &redacted(&self.return_to))
            .field("token", &redacted(&self.token))
            .field("user_code", &redacted(&self.user_code))
            .finish()
    }
}

#[derive(Deserialize)]
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
    pub(crate) reason: String,
    #[serde(default, rename = "cf-turnstile-response")]
    pub(crate) turnstile_response: String,
    #[serde(default)]
    pub(crate) code: String,
    #[serde(default, rename = "authRequestID")]
    pub(crate) auth_request_id: String,
    #[serde(default)]
    pub(crate) return_to: String,
}

impl fmt::Debug for AuthFormSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthFormSubmission")
            .field("csrf", &redacted(&self.csrf))
            .field("email", &redacted(&self.email))
            .field("password", &redacted(&self.password))
            .field("confirm_password", &redacted(&self.confirm_password))
            .field("name", &redacted(&self.name))
            .field("invite_code", &redacted(&self.invite_code))
            .field("reason", &redacted(&self.reason))
            .field("turnstile_response", &redacted(&self.turnstile_response))
            .field("code", &redacted(&self.code))
            .field("auth_request_id", &redacted(&self.auth_request_id))
            .field("return_to", &redacted(&self.return_to))
            .finish()
    }
}

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
    pub(crate) show_reason: bool,
    pub(crate) turnstile_site_key: String,
    pub(crate) show_totp_code: bool,
    pub(crate) forgot_password_link: bool,
    pub(crate) secondary_label: &'static str,
    pub(crate) secondary_url: String,
}

pub(crate) struct AccountAccessView {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) name: String,
    pub(crate) email_verified: bool,
    pub(crate) enabled: bool,
    pub(crate) reason: String,
    pub(crate) has_reason: bool,
    pub(crate) created_at: String,
}

impl fmt::Debug for AuthFormView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthFormView")
            .field("title", &self.title)
            .field("action", &self.action)
            .field("error", &self.error)
            .field("csrf_token", &redacted(&self.csrf_token))
            .field("auth_request_id", &redacted(&self.auth_request_id))
            .field("return_to", &redacted(&self.return_to))
            .finish_non_exhaustive()
    }
}

pub(crate) struct SetupTwoFactorView {
    pub(crate) csrf_token: String,
    pub(crate) return_to: String,
    pub(crate) qr_svg: String,
    pub(crate) secret: String,
    pub(crate) error: String,
}

impl fmt::Debug for SetupTwoFactorView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SetupTwoFactorView")
            .field("csrf_token", &redacted(&self.csrf_token))
            .field("return_to", &redacted(&self.return_to))
            .field("qr_svg", &redacted(&self.qr_svg))
            .field("secret", &redacted(&self.secret))
            .field("error", &self.error)
            .finish()
    }
}

pub(crate) struct TwoFactorRecoveryView {
    pub(crate) return_to: String,
    pub(crate) backup_codes: Vec<String>,
}

impl fmt::Debug for TwoFactorRecoveryView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwoFactorRecoveryView")
            .field("return_to", &redacted(&self.return_to))
            .field("backup_code_count", &self.backup_codes.len())
            .finish()
    }
}

pub(crate) struct DevicePageView {
    pub(crate) user_code_slots: [String; 8],
    pub(crate) csrf_token: String,
    pub(crate) error: String,
    pub(crate) approved: bool,
}

impl fmt::Debug for DevicePageView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevicePageView")
            .field("user_code_slots", &"[REDACTED]")
            .field("csrf_token", &redacted(&self.csrf_token))
            .field("error", &self.error)
            .field("approved", &self.approved)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct InvitationView {
    pub(crate) organization_name: String,
    pub(crate) email: String,
    pub(crate) inviter_name: String,
    pub(crate) role: &'static str,
}

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

impl fmt::Debug for InvitationPageView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationPageView")
            .field("invitation", &self.invitation)
            .field("token", &redacted(&self.token))
            .field("csrf_token", &redacted(&self.csrf_token))
            .field("authenticated", &self.authenticated)
            .field("email_matches", &self.email_matches)
            .field("login_url", &redacted(&self.login_url))
            .field("signup_url", &redacted(&self.signup_url))
            .field("error", &self.error)
            .finish()
    }
}

#[derive(Deserialize)]
pub(crate) struct CsrfSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
}

impl fmt::Debug for CsrfSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CsrfSubmission")
            .field("csrf", &redacted(&self.csrf))
            .finish()
    }
}

#[derive(Deserialize)]
pub(crate) struct DeviceSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) user_code_1: String,
    pub(crate) user_code_2: String,
    pub(crate) user_code_3: String,
    pub(crate) user_code_4: String,
    pub(crate) user_code_5: String,
    pub(crate) user_code_6: String,
    pub(crate) user_code_7: String,
    pub(crate) user_code_8: String,
}

impl DeviceSubmission {
    pub(crate) fn user_code(&self) -> String {
        [
            self.user_code_1.as_str(),
            self.user_code_2.as_str(),
            self.user_code_3.as_str(),
            self.user_code_4.as_str(),
            self.user_code_5.as_str(),
            self.user_code_6.as_str(),
            self.user_code_7.as_str(),
            self.user_code_8.as_str(),
        ]
        .concat()
    }
}

impl fmt::Debug for DeviceSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceSubmission")
            .field("csrf", &redacted(&self.csrf))
            .field("user_code", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
pub(crate) struct InvitationSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) token: String,
}

impl fmt::Debug for InvitationSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationSubmission")
            .field("csrf", &redacted(&self.csrf))
            .field("token", &redacted(&self.token))
            .finish()
    }
}

fn redacted(value: &str) -> Option<&'static str> {
    (!value.is_empty()).then_some("[REDACTED]")
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitIdentitySubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) git_name: String,
    pub(crate) git_email: String,
}

#[derive(Debug, Default)]
pub(crate) struct SettingsData {
    pub(crate) git_identity_available: bool,
    pub(crate) git_name: String,
    pub(crate) git_email: String,
}

#[derive(Default)]
pub(crate) struct SettingsPageView {
    pub(crate) account_id: String,
    pub(crate) account_name: String,
    pub(crate) account_email: String,
    pub(crate) email_verified: bool,
    pub(crate) account_created: String,
    pub(crate) two_factor_enabled: bool,
    pub(crate) sessions_available: bool,
    pub(crate) current_session_id: String,
    pub(crate) current_session_expiry: String,
    pub(crate) sessions: Vec<AccountSessionRowView>,
    pub(crate) next_sessions_url: String,
    pub(crate) first_sessions_url: String,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Default)]
pub(crate) struct AccountSessionRowView {
    pub(crate) id: String,
    pub(crate) created: String,
    pub(crate) expires: String,
    pub(crate) current: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialChoiceView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) status: &'static str,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CredentialChoicesView {
    pub(crate) codex: Vec<CredentialChoiceView>,
    pub(crate) openai: Vec<CredentialChoiceView>,
    pub(crate) github: Vec<CredentialChoiceView>,
    pub(crate) anthropic: Vec<CredentialChoiceView>,
    pub(crate) ssh: Vec<CredentialChoiceView>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialRowView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) provider: &'static str,
    pub(crate) authentication: &'static str,
    pub(crate) account_hint: String,
    pub(crate) status: &'static str,
    pub(crate) status_tone: &'static str,
    pub(crate) expires: String,
    pub(crate) generation: u64,
    pub(crate) ssh_public_key: String,
    pub(crate) ssh_fingerprint: String,
    pub(crate) public_key_id: String,
    pub(crate) api_key: bool,
    pub(crate) oauth: bool,
    pub(crate) revoked: bool,
    pub(crate) oauth_provider: &'static str,
}

impl CredentialRowView {
    pub(crate) fn display_name(&self) -> &str {
        if self.oauth_provider == "github" && !self.account_hint.is_empty() {
            &self.account_hint
        } else {
            &self.name
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialProfileEntryView {
    pub(crate) slot: &'static str,
    pub(crate) credential: String,
    pub(crate) status: &'static str,
    pub(crate) status_tone: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialProfileRowView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) revision: u64,
    pub(crate) entries: Vec<CredentialProfileEntryView>,
    pub(crate) codex: String,
    pub(crate) openai: String,
    pub(crate) github: String,
    pub(crate) anthropic: String,
    pub(crate) ssh: String,
}

pub(crate) struct CredentialSettingsView {
    pub(crate) navigation_query: String,
    pub(crate) creation_return_url: String,
    pub(crate) git_identity: SettingsData,
    pub(crate) git_identity_feedback: bool,
    pub(crate) active_dialog: String,
    pub(crate) github_install_url: String,
    pub(crate) credentials: Vec<CredentialRowView>,
    pub(crate) profiles: Vec<CredentialProfileRowView>,
    pub(crate) choices: CredentialChoicesView,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

impl CredentialSettingsView {
    pub(crate) fn has_github_connections(&self) -> bool {
        self.credentials
            .iter()
            .any(|credential| credential.oauth_provider == "github")
    }
}

impl fmt::Debug for CredentialSettingsView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialSettingsView")
            .field("credential_count", &self.credentials.len())
            .field("profile_count", &self.profiles.len())
            .field("csrf_token", &redacted(&self.csrf_token))
            .field("message", &self.message)
            .field("error", &self.error)
            .finish()
    }
}

#[derive(Deserialize)]
pub(crate) struct CredentialProfileCreateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) codex: String,
    #[serde(default)]
    pub(crate) openai: String,
    #[serde(default)]
    pub(crate) github: String,
    #[serde(default)]
    pub(crate) anthropic: String,
    #[serde(default)]
    pub(crate) ssh: String,
}

#[derive(Deserialize)]
pub(crate) struct CredentialProfileUpdateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) profile_id: String,
    pub(crate) expected_revision: u64,
    #[serde(default)]
    pub(crate) codex: String,
    #[serde(default)]
    pub(crate) openai: String,
    #[serde(default)]
    pub(crate) github: String,
    #[serde(default)]
    pub(crate) anthropic: String,
    #[serde(default)]
    pub(crate) ssh: String,
}

#[derive(Deserialize)]
pub(crate) struct CredentialProfileDeleteSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) profile_id: String,
    pub(crate) expected_revision: u64,
}

// Deliberately not Debug: submitted API-key material must not enter derived
// diagnostics or a retained form model.
#[derive(Deserialize)]
pub(crate) struct CredentialApiKeySubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) provider: String,
    pub(crate) name: String,
    pub(crate) value: String,
    #[serde(default)]
    pub(crate) expiration_utc: String,
}

#[derive(Deserialize)]
pub(crate) struct CredentialSshGenerateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) expiration_utc: String,
}

// Deliberately not Debug: private key and passphrase are write-only inputs.
#[derive(Deserialize)]
pub(crate) struct CredentialSshImportSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) name: String,
    pub(crate) private_key: String,
    #[serde(default)]
    pub(crate) passphrase: String,
    #[serde(default)]
    pub(crate) expiration_utc: String,
}

#[derive(Deserialize)]
pub(crate) struct CredentialRenameSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) credential_id: String,
    pub(crate) expected_revocation_generation: u64,
    pub(crate) expected_name: String,
    pub(crate) name: String,
}

// Deliberately not Debug: replacement API-key material is write-only.
#[derive(Deserialize)]
pub(crate) struct CredentialRotateSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) credential_id: String,
    pub(crate) expected_revocation_generation: u64,
    pub(crate) value: String,
    #[serde(default)]
    pub(crate) expiration_utc: String,
}

#[derive(Deserialize)]
pub(crate) struct CredentialRevisionSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) credential_id: String,
    pub(crate) expected_revocation_generation: u64,
}

// Deliberately not Debug: the stream may expose a one-time device code only in
// its no-store response, never through a retained submission diagnostic.
#[derive(Deserialize)]
pub(crate) struct CredentialOAuthSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    pub(crate) provider: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) credential_id: String,
    #[serde(default)]
    pub(crate) expected_revocation_generation: Option<u64>,
    #[serde(default)]
    pub(crate) confirm_reconnect: String,
}

// Deliberately not Debug: although this form has no provider material, it
// starts an authorization redirect and carries a session-bound CSRF token.
#[derive(Deserialize)]
pub(crate) struct GitHubAppAuthorizationSubmission {
    #[serde(rename = "_csrf")]
    pub(crate) csrf: String,
    #[serde(default)]
    pub(crate) credential_id: String,
    #[serde(default)]
    pub(crate) expected_revocation_generation: Option<u64>,
    #[serde(default)]
    pub(crate) confirm_reconnect: String,
}

#[derive(Debug, Default)]
pub(crate) struct DashboardView {
    pub(crate) user_name: String,
    pub(crate) is_admin: bool,
    pub(crate) organizations: Vec<OrganizationRow>,
    pub(crate) has_organizations: bool,
    pub(crate) organization_navigation_unavailable: bool,
    pub(crate) show_checklist: bool,
    pub(crate) new_organization_url: String,
    pub(crate) settings_url: String,
    pub(crate) global_context_query: String,
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
    pub(crate) can_admin: bool,
    pub(crate) environments_url: String,
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
            can_admin: row.can_admin,
            environments_url: format!("{local_base}/"),
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
    pub(crate) deletion_state: &'static str,
    pub(crate) shutdown_at: Option<String>,
    pub(crate) shutdown_at_label: String,
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
    pub(crate) sources: Option<EnvironmentSourcesSummaryView>,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentSourcesSummaryView {
    pub(crate) selection: codewire_proto::codewire::v1::EnvironmentSourceSelection,
    pub(crate) operation_generation: u64,
    pub(crate) project: String,
    pub(crate) organization: bool,
    pub(crate) personal: bool,
    pub(crate) profile: String,
    pub(crate) profile_revision: String,
}

impl EnvironmentSourcesSummaryView {
    pub(crate) fn project_id(&self) -> &str {
        self.project
            .strip_prefix("platform:id:")
            .unwrap_or_default()
    }

    pub(crate) fn profile_id(&self) -> &str {
        self.profile
            .strip_prefix("platform:id:")
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentSourcesEditView {
    pub(crate) environment_id: String,
    pub(crate) environment_name: String,
    pub(crate) expected: EnvironmentSourcesSummaryView,
    pub(crate) fields: EnvironmentSourceFieldsView,
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

fn resize_detail_url(slug: &str, environment_id: &str) -> Option<String> {
    if !codewire_server_core::organization_slug::valid_organization_slug(slug)
        || !uuid::Uuid::parse_str(environment_id).is_ok_and(|id| id.to_string() == environment_id)
    {
        return None;
    }
    Some(format!("/{slug}/{environment_id}/"))
}

impl EnvironmentResizeConfirmationView {
    pub(crate) fn detail_url(&self, slug: &str) -> Option<String> {
        resize_detail_url(slug, &self.environment_id)
    }
}

impl EnvironmentResizeOperationView {
    pub(crate) fn detail_url(&self, slug: &str) -> Option<String> {
        resize_detail_url(slug, &self.environment_id)
    }
}

#[cfg(test)]
mod resize_detail_link_tests {
    use super::resize_detail_url;

    #[test]
    fn native_resize_return_links_only_use_canonical_same_org_paths() {
        let environment = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        assert_eq!(
            resize_detail_url("example-org", environment),
            Some(format!("/example-org/{environment}/"))
        );
        for slug in [
            "../foreign",
            "//foreign",
            "https://foreign.test",
            "",
            "UPPERCASE",
        ] {
            assert!(resize_detail_url(slug, environment).is_none());
        }
        for environment in [
            "../foreign",
            "environment-id",
            "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
            "",
        ] {
            assert!(resize_detail_url("example-org", environment).is_none());
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TerminalPageView {
    pub(crate) account_id: String,
    pub(crate) organization_id: String,
    pub(crate) environment: EnvironmentRow,
    pub(crate) websocket_origin: String,
    pub(crate) list_context: SandboxListContext,
    pub(crate) list_url: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

/// Navigation metadata only: neither an organization authority nor a return URL.
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct SandboxListContext {
    #[serde(default)]
    pub(crate) list_search: String,
    #[serde(default)]
    pub(crate) list_state: String,
}

impl SandboxListContext {
    pub(crate) fn new(search: &str, state: &str) -> Self {
        Self {
            list_search: search
                .chars()
                .filter(|character| !character.is_control())
                .take(128)
                .collect(),
            list_state: Self::state(state).to_owned(),
        }
    }

    pub(crate) fn normalized(&self) -> Self {
        Self::new(&self.list_search, &self.list_state)
    }

    pub(crate) fn state(value: &str) -> &'static str {
        match value {
            "running" => "running",
            "stopped" => "stopped",
            "pending" => "pending",
            "creating" => "creating",
            "starting" => "starting",
            "stopping" => "stopping",
            "error" => "error",
            "destroyed" => "destroyed",
            _ => "all",
        }
    }

    pub(crate) fn list_url(&self, slug: &str) -> String {
        self.path(slug, None)
    }

    pub(crate) fn detail_url(&self, slug: &str, environment_id: &str) -> String {
        self.path(slug, Some(environment_id))
    }

    fn path(&self, slug: &str, environment_id: Option<&str>) -> String {
        if !codewire_server_core::organization_slug::valid_organization_slug(slug) {
            return "/dashboard/".to_owned();
        }
        let detail = environment_id.and_then(|id| resize_detail_url(slug, id));
        let mut path = detail.clone().unwrap_or_else(|| format!("/{slug}/"));
        let context = self.normalized();
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if !context.list_search.is_empty() {
            query.append_pair(
                if detail.is_some() {
                    "list_search"
                } else {
                    "search"
                },
                &context.list_search,
            );
        }
        if context.list_state != "all" {
            query.append_pair(
                if detail.is_some() {
                    "list_state"
                } else {
                    "state"
                },
                &context.list_state,
            );
        }
        let query = query.finish();
        if !query.is_empty() {
            path.push('?');
            path.push_str(&query);
        }
        path
    }
}

#[cfg(test)]
mod sandbox_list_context_tests {
    use super::SandboxListContext;

    const ENVIRONMENT: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    #[test]
    fn navigation_context_is_bounded_metadata_not_a_return_url() {
        let context = SandboxListContext::new(
            &format!("\n{}\t", "界".repeat(129)),
            "https://other.invalid/",
        );
        assert_eq!(context.list_search, "界".repeat(128));
        assert_eq!(context.list_state, "all");
        assert_eq!(SandboxListContext::default().list_url("my-org"), "/my-org/");
        assert_eq!(
            SandboxListContext::default().detail_url("my-org", ENVIRONMENT),
            format!("/my-org/{ENVIRONMENT}/")
        );
        assert_eq!(
            context.detail_url("../other-org", ENVIRONMENT),
            "/dashboard/"
        );
        assert_eq!(
            context.detail_url("//other.invalid", ENVIRONMENT),
            "/dashboard/"
        );
        assert!(
            context
                .detail_url("my-org", "../other-org")
                .starts_with("/my-org/?search=")
        );
    }

    #[test]
    fn list_and_detail_encode_search_without_changing_path_or_state() {
        let search = "雪 &state=destroyed?return_to=https://other.invalid/#fragment";
        let context = SandboxListContext::new(search, "running");
        for (path, expected_path, search_key, state_key) in [
            (
                context.list_url("my-org"),
                "/my-org/".to_owned(),
                "search",
                "state",
            ),
            (
                context.detail_url("my-org", ENVIRONMENT),
                format!("/my-org/{ENVIRONMENT}/"),
                "list_search",
                "list_state",
            ),
        ] {
            let parsed = url::Url::parse(&format!("https://dashboard.invalid{path}")).unwrap();
            assert_eq!(parsed.path(), expected_path);
            assert_eq!(parsed.host_str(), Some("dashboard.invalid"));
            assert_eq!(parsed.fragment(), None);
            assert_eq!(
                parsed.query_pairs().collect::<Vec<_>>(),
                vec![
                    (search_key.into(), search.into()),
                    (state_key.into(), "running".into())
                ]
            );
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentPresetOption {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) image: String,
    pub(crate) default_cpu_millicores: Option<u32>,
    pub(crate) default_memory_mib: Option<u64>,
    pub(crate) default_disk_gib: Option<u64>,
    pub(crate) default_ttl_seconds: Option<i32>,
    pub(crate) default_install_command: String,
    pub(crate) default_startup_script: String,
    pub(crate) default_agents: Vec<String>,
    pub(crate) default_app_ports: Vec<EnvironmentAppPortFormRow>,
    pub(crate) uses_protected_secret_bindings: bool,
    pub(crate) official: bool,
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

#[derive(Clone, Debug, Default)]
pub(crate) struct EnvironmentAppPortFormRow {
    pub(crate) index: usize,
    pub(crate) port: String,
    pub(crate) label: String,
    pub(crate) access: String,
    pub(crate) port_error: String,
    pub(crate) label_error: String,
    pub(crate) access_error: String,
}

impl EnvironmentAppPortFormRow {
    pub(crate) fn access_selected(&self, value: &str) -> bool {
        self.access == value
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentAgentView {
    pub(crate) id: &'static str,
    pub(crate) label: &'static str,
}

/// Selection metadata only. No application value or provider material belongs
/// in a form model, including when an upstream selection cannot be loaded.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnvironmentSourceFieldsView {
    pub(crate) selection: Option<codewire_proto::codewire::v1::EnvironmentSourceSelection>,
    pub(crate) personal_selected: bool,
    pub(crate) organization_selected: bool,
    pub(crate) projects: Vec<EnvironmentSecretProjectOption>,
    pub(crate) profiles: Vec<EnvironmentCredentialProfileOption>,
    pub(crate) project_error: String,
    pub(crate) profile_error: String,
    pub(crate) project_selection_error: String,
    pub(crate) profile_selection_error: String,
    // Readable metadata is not proof that a placement can deliver it. The
    // mutation adapter enables these only with the corresponding backend path.
    pub(crate) application_selection_enabled: bool,
    pub(crate) credential_selection_enabled: bool,
    pub(crate) personal_credentials_confirmed: bool,
    pub(crate) personal_secrets_confirmed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentSecretProjectOption {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) selected: bool,
    pub(crate) synthetic: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentCredentialProfileOption {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) revision: u64,
    pub(crate) identity_count: usize,
    pub(crate) bound_revision: bool,
    pub(crate) synthetic: bool,
    pub(crate) selected: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct EnvironmentCreateFormView {
    pub(crate) csrf_token: String,
    pub(crate) draft_actor: String,
    pub(crate) draft_organization: String,
    pub(crate) draft_id: String,
    pub(crate) draft_return: crate::environment_drafts::DraftReturn,
    pub(crate) draft_restore_allowed: bool,
    pub(crate) draft_restored: bool,
    pub(crate) expanded: bool,
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
    pub(crate) preview_base_domain: String,
    pub(crate) selected_agents: Vec<String>,
    pub(crate) app_ports: Vec<EnvironmentAppPortFormRow>,
    pub(crate) presets: Vec<EnvironmentPresetOption>,
    pub(crate) agents: Vec<EnvironmentAgentView>,
    pub(crate) sources: EnvironmentSourceFieldsView,
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
    /// Navigation metadata only; derive it from the final form, not catalogs.
    pub(crate) fn creation_draft_parameter(&self) -> String {
        if crate::environment_drafts::canonical_id(&self.draft_id) {
            format!("creation_draft={}", self.draft_id)
        } else {
            String::new()
        }
    }

    pub(crate) fn cpu_uses_catalog_option(&self) -> bool {
        matches!(self.cpu.as_str(), "1000" | "2000" | "4000" | "8000")
    }

    pub(crate) fn memory_uses_catalog_option(&self) -> bool {
        matches!(self.memory.as_str(), "2048" | "4096" | "8192" | "16384")
    }

    pub(crate) fn disk_uses_catalog_option(&self) -> bool {
        matches!(self.disk.as_str(), "10" | "20" | "40" | "80")
    }

    pub(crate) fn isolation_selected(&self, value: &str) -> bool {
        self.isolation_tier == value
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
            || !self.sources.project_error.is_empty()
            || !self.sources.profile_error.is_empty()
            || !self.sources.project_selection_error.is_empty()
            || !self.sources.profile_selection_error.is_empty()
            || self.app_ports.iter().any(|row| {
                !row.port_error.is_empty()
                    || !row.label_error.is_empty()
                    || !row.access_error.is_empty()
            })
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
    pub(crate) port_error: String,
    pub(crate) label_error: String,
    pub(crate) access_error: String,
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
    pub(crate) source_editor: Option<EnvironmentSourcesEditView>,
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
    pub(crate) fn detail_url(&self, slug: &str, environment_id: &str) -> String {
        SandboxListContext::new(&self.search, &self.state).detail_url(slug, environment_id)
    }

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

// Deliberately not Debug: a post-create rendering may contain the one-time
// invitation URL. List/read paths always leave that field empty.
pub(crate) struct MembersPageView {
    pub(crate) members: Vec<MemberRow>,
    pub(crate) invitations: Vec<InvitationRow>,
    pub(crate) assignment_options: &'static [AssignmentView],
    pub(crate) invite_form: InviteFormView,
    pub(crate) csrf_token: String,
    pub(crate) one_time_invitation_url: String,
    pub(crate) has_one_time_invitation: bool,
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
pub(crate) struct PersonalApiKeyRow {
    pub(crate) key: ApiKeyRow,
    pub(crate) expires: String,
    pub(crate) scopes: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct PersonalApiKeyGroupView {
    pub(crate) organization: OrganizationRow,
    pub(crate) keys: Vec<PersonalApiKeyRow>,
    pub(crate) available: bool,
    pub(crate) truncated: bool,
}

#[derive(Default)]
pub(crate) struct PersonalApiKeyFormView {
    pub(crate) org_id: String,
    pub(crate) name: String,
    pub(crate) expiration: String,
    pub(crate) error: String,
    pub(crate) expanded: bool,
}

// Only a successful Create response can populate one_time_key. Never derive
// diagnostics for this model or persist it as navigation/history state.
#[derive(Default)]
pub(crate) struct PersonalApiKeysPageView {
    pub(crate) groups: Vec<PersonalApiKeyGroupView>,
    pub(crate) organizations: Vec<OrganizationRow>,
    pub(crate) organizations_available: bool,
    pub(crate) account_id: String,
    pub(crate) csrf_token: String,
    pub(crate) form: PersonalApiKeyFormView,
    pub(crate) one_time_key: String,
    pub(crate) one_time_name: String,
    pub(crate) one_time_organization: String,
    pub(crate) message: String,
    pub(crate) error: String,
    pub(crate) action_query: String,
    pub(crate) reload_url: String,
    pub(crate) first_page_url: String,
    pub(crate) next_page_url: String,
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
    pub(crate) creation_draft_query: String,
    pub(crate) creation_return_url: String,
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

// Only metadata is retained. Submitted values must never enter a page view.
#[derive(Default)]
pub(crate) struct PersonalSecretsPageView {
    pub(crate) creation_return_url: String,
    pub(crate) reload_url: String,
    pub(crate) account_id: String,
    pub(crate) secrets: Vec<SecretRow>,
    pub(crate) available: bool,
    pub(crate) form: SecretFormView,
    pub(crate) new_key: String,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
    pub(crate) active_dialog: String,
    pub(crate) first_page_url: String,
    pub(crate) next_page_url: String,
    pub(crate) action_query: String,
}

impl fmt::Debug for PersonalSecretsPageView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonalSecretsPageView")
            .field("account_id", &self.account_id)
            .field("secret_count", &self.secrets.len())
            .field("available", &self.available)
            .field("csrf_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct SecretBucketPageView {
    pub(crate) creation_draft_query: String,
    pub(crate) creation_return_url: String,
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

#[cfg(test)]
mod secret_debug_tests {
    use super::*;

    const MARKER: &str = "synthetic-secret-capability-marker";

    fn assert_value_blind(diagnostic: &str) {
        assert!(!diagnostic.contains(MARKER));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[test]
    fn auth_input_debug_redacts_credentials_and_continuations() {
        let query = AuthQuery {
            auth_request_id: MARKER.into(),
            return_to: format!("/accept-invite?token={MARKER}"),
            token: MARKER.into(),
            user_code: MARKER.into(),
        };
        let submission = AuthFormSubmission {
            csrf: MARKER.into(),
            email: MARKER.into(),
            password: MARKER.into(),
            confirm_password: MARKER.into(),
            name: MARKER.into(),
            invite_code: MARKER.into(),
            reason: MARKER.into(),
            turnstile_response: MARKER.into(),
            code: MARKER.into(),
            auth_request_id: MARKER.into(),
            return_to: MARKER.into(),
        };

        assert_value_blind(&format!("{query:?}"));
        assert_value_blind(&format!("{submission:?}"));
        assert_value_blind(&format!(
            "{:?}",
            CsrfSubmission {
                csrf: MARKER.into()
            }
        ));
    }

    #[test]
    fn two_factor_and_device_debug_redact_capabilities() {
        let setup = SetupTwoFactorView {
            csrf_token: MARKER.into(),
            return_to: MARKER.into(),
            qr_svg: MARKER.into(),
            secret: MARKER.into(),
            error: String::new(),
        };
        let recovery = TwoFactorRecoveryView {
            return_to: MARKER.into(),
            backup_codes: vec![MARKER.into()],
        };
        let device = DevicePageView {
            user_code_slots: std::array::from_fn(|_| MARKER.into()),
            csrf_token: MARKER.into(),
            error: String::new(),
            approved: false,
        };
        let submission = DeviceSubmission {
            csrf: MARKER.into(),
            user_code_1: MARKER.into(),
            user_code_2: MARKER.into(),
            user_code_3: MARKER.into(),
            user_code_4: MARKER.into(),
            user_code_5: MARKER.into(),
            user_code_6: MARKER.into(),
            user_code_7: MARKER.into(),
            user_code_8: MARKER.into(),
        };

        for diagnostic in [
            format!("{setup:?}"),
            format!("{recovery:?}"),
            format!("{device:?}"),
            format!("{submission:?}"),
        ] {
            assert_value_blind(&diagnostic);
        }
    }

    #[test]
    fn credential_settings_debug_redacts_csrf_capability() {
        let page = CredentialSettingsView {
            navigation_query: String::new(),
            creation_return_url: String::new(),
            git_identity: SettingsData::default(),
            git_identity_feedback: false,
            active_dialog: String::new(),
            github_install_url: String::new(),
            credentials: Vec::new(),
            profiles: Vec::new(),
            choices: CredentialChoicesView::default(),
            csrf_token: MARKER.into(),
            message: String::new(),
            error: String::new(),
        };

        assert_value_blind(&format!("{page:?}"));
    }

    #[test]
    fn invitation_debug_redacts_token_and_token_bearing_urls() {
        let page = InvitationPageView {
            invitation: InvitationView {
                organization_name: "Synthetic Organization".into(),
                email: "invitee@example.test".into(),
                inviter_name: "Synthetic Owner".into(),
                role: "Member",
            },
            token: MARKER.into(),
            csrf_token: MARKER.into(),
            authenticated: true,
            email_matches: true,
            login_url: format!("/login?return_to=/accept-invite%3Ftoken%3D{MARKER}"),
            signup_url: format!("/signup?return_to=/accept-invite%3Ftoken%3D{MARKER}"),
            error: String::new(),
        };
        let submission = InvitationSubmission {
            csrf: MARKER.into(),
            token: MARKER.into(),
        };

        assert_value_blind(&format!("{page:?}"));
        assert_value_blind(&format!("{submission:?}"));
    }
}
