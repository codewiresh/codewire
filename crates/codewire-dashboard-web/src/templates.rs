use askama::Template;

use crate::admin_connect::{AdminCatalogView, AdminStatsView, AuditLogRow};
use crate::billing_connect::BillingPageView;
use crate::view::EnvironmentCreateFormView;
use crate::view::{
    AccountAccessView, ApiKeysPageView, AuthFormView, CredentialSettingsView, DashboardView,
    DevicePageView, EnvironmentsPageView, InvitationPageView, MembersPageView, OrganizationContext,
    OrganizationFormView, OrganizationRow, PresetsPageView, SecretBucketPageView,
    SecretProjectsPageView, SettingsPageView, SettingsPlaceholderView, SetupTwoFactorView,
    TerminalPageView, TwoFactorRecoveryView,
};

#[derive(Template)]
#[template(path = "home.html")]
pub(crate) struct HomeTemplate;

#[derive(Template)]
#[template(path = "admin-overview.html")]
pub(crate) struct AdminOverviewTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) stats: &'a AdminStatsView,
}

#[derive(Template)]
#[template(path = "admin-accounts.html")]
pub(crate) struct AdminAccountsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) accounts: &'a [AccountAccessView],
    pub(crate) csrf_token: &'a str,
    pub(crate) message: &'a str,
    pub(crate) error: &'a str,
}

#[derive(Template)]
#[template(path = "admin-audit.html")]
pub(crate) struct AdminAuditTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) logs: &'a [AuditLogRow],
    pub(crate) action: &'a str,
    pub(crate) info_selected: bool,
    pub(crate) warn_selected: bool,
    pub(crate) error_selected: bool,
    pub(crate) has_previous: bool,
    pub(crate) has_next: bool,
    pub(crate) previous_url: &'a str,
    pub(crate) next_url: &'a str,
}

#[derive(Template)]
#[template(path = "admin-billing.html")]
pub(crate) struct AdminBillingTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) catalog: &'a AdminCatalogView,
}

#[derive(Template)]
#[template(path = "auth-form.html")]
pub(crate) struct AuthFormTemplate<'a> {
    pub(crate) view: &'a AuthFormView,
}

#[derive(Template)]
#[template(path = "auth-status.html")]
pub(crate) struct AuthStatusTemplate<'a> {
    pub(crate) title: &'a str,
    pub(crate) description: &'a str,
    pub(crate) primary_label: &'a str,
    pub(crate) primary_url: &'a str,
}

#[derive(Template)]
#[template(path = "setup-two-factor.html")]
pub(crate) struct SetupTwoFactorTemplate<'a> {
    pub(crate) view: &'a SetupTwoFactorView,
}

#[derive(Template)]
#[template(path = "two-factor-recovery.html")]
pub(crate) struct TwoFactorRecoveryTemplate<'a> {
    pub(crate) view: &'a TwoFactorRecoveryView,
}

#[derive(Template)]
#[template(path = "device.html")]
pub(crate) struct DeviceTemplate<'a> {
    pub(crate) view: &'a DevicePageView,
}

#[derive(Template)]
#[template(path = "invitation.html")]
pub(crate) struct InvitationTemplate<'a> {
    pub(crate) view: &'a InvitationPageView,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub(crate) struct SettingsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) settings: &'a SettingsPageView,
}

#[derive(Template)]
#[template(path = "settings-credentials.html")]
pub(crate) struct CredentialSettingsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a CredentialSettingsView,
}

#[derive(Template)]
#[template(path = "settings-placeholder.html")]
pub(crate) struct SettingsPlaceholderTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a SettingsPlaceholderView,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub(crate) struct DashboardTemplate<'a> {
    pub(crate) view: &'a DashboardView,
}

#[derive(Template)]
#[template(path = "organization-list.html")]
pub(crate) struct OrganizationListTemplate<'a> {
    pub(crate) organizations: &'a [OrganizationRow],
    pub(crate) has_organizations: bool,
}

#[derive(Template)]
#[template(path = "new-organization.html")]
pub(crate) struct NewOrganizationTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) form: &'a OrganizationFormView,
    pub(crate) csrf_token: &'a str,
}

#[derive(Template)]
#[template(path = "organization-form.html")]
pub(crate) struct OrganizationFormTemplate<'a> {
    pub(crate) form: &'a OrganizationFormView,
    pub(crate) csrf_token: &'a str,
}

#[derive(Template)]
#[template(path = "organization-members.html")]
pub(crate) struct OrganizationMembersTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a MembersPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-members-content.html")]
pub(crate) struct OrganizationMembersContentTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a MembersPageView,
}

#[derive(Template)]
#[template(path = "organization-api-keys.html")]
pub(crate) struct OrganizationApiKeysTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a ApiKeysPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-billing.html")]
pub(crate) struct OrganizationBillingTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) billing: &'a BillingPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-api-keys-content.html")]
pub(crate) struct OrganizationApiKeysContentTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a ApiKeysPageView,
}

#[derive(Template)]
#[template(path = "organization-secrets.html")]
pub(crate) struct OrganizationSecretsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a SecretProjectsPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-secrets-content.html")]
pub(crate) struct OrganizationSecretsContentTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a SecretProjectsPageView,
}

#[derive(Template)]
#[template(path = "organization-secret-bucket.html")]
pub(crate) struct OrganizationSecretBucketTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a SecretBucketPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-secret-bucket-content.html")]
pub(crate) struct OrganizationSecretBucketContentTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a SecretBucketPageView,
}

#[derive(Template)]
#[template(path = "organization-presets.html")]
pub(crate) struct OrganizationPresetsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a PresetsPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-presets-content.html")]
pub(crate) struct OrganizationPresetsContentTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a PresetsPageView,
}

#[derive(Template)]
#[template(path = "organization-environments.html")]
pub(crate) struct OrganizationEnvironmentsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a EnvironmentsPageView,
}

#[derive(Template)]
#[template(path = "organization-environments-content.html")]
pub(crate) struct OrganizationEnvironmentsContentTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a EnvironmentsPageView,
}

#[derive(Template)]
#[template(path = "snapshots.html")]
pub(crate) struct SnapshotsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
}

#[derive(Template)]
#[template(path = "environment-create-form.html")]
pub(crate) struct EnvironmentCreateFormTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) form: &'a EnvironmentCreateFormView,
}

#[derive(Template)]
#[template(path = "environment-list.html")]
pub(crate) struct EnvironmentListTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a EnvironmentsPageView,
}

#[derive(Template)]
#[template(path = "sandbox-rail.html")]
pub(crate) struct SandboxRailTemplate<'a> {
    pub(crate) view: &'a DashboardView,
}

#[derive(Template)]
#[template(path = "environment-resize-operation.html")]
pub(crate) struct EnvironmentResizeOperationTemplate<'a> {
    pub(crate) organization: &'a crate::view::OrganizationContext,
    pub(crate) operation: &'a crate::view::EnvironmentResizeOperationView,
}

#[derive(Template)]
#[template(path = "terminal.html")]
pub(crate) struct TerminalTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a TerminalPageView,
    pub(crate) csrf_token: &'a str,
    pub(crate) style_nonce: &'a str,
}

#[derive(Template)]
#[template(path = "environment-ports.html")]
pub(crate) struct EnvironmentPortsTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) panel: &'a crate::view::EnvironmentPortPanelView,
    pub(crate) csrf_token: &'a str,
    pub(crate) in_dialog: bool,
    pub(crate) message: &'a str,
}

#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate<'a> {
    pub(crate) message: &'a str,
}
