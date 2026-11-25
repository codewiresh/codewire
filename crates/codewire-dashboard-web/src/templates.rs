use askama::Template;

use crate::account_home::Balance;
use crate::admin_connect::{
    AdminCatalogView, AdminOrganizationView, AdminOrganizations, AdminStatsView, AuditLogRow,
    FeedbackFilter, FeedbackRow, FeedbackSenderView, QuotaView, pricing::PricingPageView,
};
use crate::billing_banner::BillingBannerView;
use crate::billing_connect::BillingPageView;
use crate::view::EnvironmentCreateFormView;
use crate::view::InvitationState;
use crate::view::{
    AccountAccessView, AccountDeletionPageView, AdminAccountDeletionView, ApiKeysPageView,
    AuthFormView, CredentialSettingsView, DashboardView, DevicePageView, EnvironmentRow,
    EnvironmentsPageView, GithubAcceptView, InvitationPageView, MembersPageView,
    OrganizationContext, OrganizationFormView, OrganizationRow, PersonalApiKeysPageView,
    PersonalSecretsPageView, PresetsPageView, SecretBucketPageView, SecretProjectsPageView,
    SettingsPageView, SetupTwoFactorView, TerminalPageView, TwoFactorRecoveryView,
};

#[derive(Template)]
#[template(path = "home.html")]
pub(crate) struct HomeTemplate {
    /// Where this deployment is served, for the share tags' absolute URLs.
    pub(crate) public_origin: String,
}

#[derive(Template)]
#[template(path = "pricing.html")]
pub(crate) struct PricingTemplate {
    /// Where this deployment is served, for the share tags' absolute URLs.
    pub(crate) public_origin: String,
    /// The sign-up credit as the page says it ("€10"), or `None` when there
    /// is none and the page promises nothing.
    pub(crate) signup_credit: Option<String>,
    /// Regular's rates, or `None` when billing has never answered and the
    /// page shows no prices.
    pub(crate) rates: Option<crate::public_rates::PricingRatesView>,
}

#[derive(Template)]
#[template(path = "privacy.html")]
pub(crate) struct PrivacyTemplate {
    /// Where this deployment is served, for the share tags' absolute URLs.
    pub(crate) public_origin: String,
}

#[derive(Template)]
#[template(path = "terms.html")]
pub(crate) struct TermsTemplate {
    /// Where this deployment is served, for the share tags' absolute URLs.
    pub(crate) public_origin: String,
}

/// The public Updates page. `posts` is `None` when Liminal has never answered.
#[derive(Template)]
#[template(path = "updates.html")]
pub(crate) struct UpdatesTemplate {
    /// Where this deployment is served, for the share tags' absolute URLs.
    pub(crate) public_origin: String,
    pub(crate) posts: Option<std::sync::Arc<Vec<crate::updates_connect::UpdatePost>>>,
}

#[derive(Template)]
#[template(path = "settings-secrets.html")]
pub(crate) struct SettingsSecretsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a PersonalSecretsPageView,
}

#[derive(Template)]
#[template(path = "settings-api-keys.html")]
pub(crate) struct SettingsApiKeysTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a PersonalApiKeysPageView,
}

#[derive(Template)]
#[template(path = "admin-overview.html")]
pub(crate) struct AdminOverviewTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) stats: &'a AdminStatsView,
}

#[derive(Template)]
#[template(path = "admin-organizations.html")]
pub(crate) struct AdminOrganizationsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organizations: &'a AdminOrganizations,
    pub(crate) defaults: &'a QuotaView,
    pub(crate) csrf_token: &'a str,
    pub(crate) message: &'a str,
    pub(crate) error: &'a str,
}

#[derive(Template)]
#[template(path = "admin-organization.html")]
pub(crate) struct AdminOrganizationTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a AdminOrganizationView,
    pub(crate) csrf_token: &'a str,
    /// A fresh key for the credit form, so a resubmitted form applies its
    /// adjustment once (#3381).
    pub(crate) credit_key: &'a str,
    /// An adjustment below zero awaiting the administrator's answer (#4754).
    pub(crate) credit_confirmation: Option<&'a crate::admin_connect::CreditConfirmationView>,
    pub(crate) message: &'a str,
    pub(crate) error: &'a str,
}

#[derive(Template)]
#[template(path = "admin-accounts.html")]
pub(crate) struct AdminAccountsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) accounts: &'a [AccountAccessView],
    /// Narrowed to one account, as from a feedback row.
    pub(crate) one_account: bool,
    pub(crate) csrf_token: &'a str,
    pub(crate) message: &'a str,
    pub(crate) error: &'a str,
}

#[derive(Template)]
#[template(path = "admin-account-delete.html")]
pub(crate) struct AdminAccountDeleteTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a AdminAccountDeletionView,
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
#[template(path = "admin-feedback.html")]
pub(crate) struct AdminFeedbackTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) rows: &'a [FeedbackRow],
    pub(crate) filter: FeedbackFilter,
    /// Showing a page after the first, so an empty one is not "no feedback yet".
    pub(crate) later_page: bool,
    pub(crate) first_page_url: &'a str,
    pub(crate) next_page_url: &'a str,
}

#[derive(Template)]
#[template(path = "admin-billing.html")]
pub(crate) struct AdminBillingTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) catalog: &'a AdminCatalogView,
}

#[derive(Template)]
#[template(path = "admin-pricing.html")]
pub(crate) struct AdminPricingTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a PricingPageView,
}

#[derive(Template)]
#[template(path = "auth-form.html")]
pub(crate) struct AuthFormTemplate<'a> {
    pub(crate) view: &'a AuthFormView,
}

#[derive(Template)]
#[template(path = "settings-delete-account.html")]
pub(crate) struct AccountDeletionTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) page: &'a AccountDeletionPageView,
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

/// The invitation page before it knows which invitation (#3840): its script
/// posts the link's fragment token, or says there is nothing to open.
#[derive(Template)]
#[template(path = "invitation-opening.html")]
pub(crate) struct InvitationOpeningTemplate<'a> {
    pub(crate) csrf_token: &'a str,
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
#[template(path = "settings-github-permissions.html")]
pub(crate) struct GithubPermissionsTemplate<'a> {
    pub(crate) pending: &'a [GithubAcceptView],
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub(crate) struct DashboardTemplate<'a> {
    pub(crate) view: &'a DashboardView,
}

/// The account home's shell: the checklist and organization cards load
/// after it as `AccountOverviewTemplate`.
#[derive(Template)]
#[template(path = "account-home.html")]
pub(crate) struct AccountHomeTemplate<'a> {
    pub(crate) view: &'a DashboardView,
}

#[derive(Template)]
#[template(path = "account-overview.html")]
pub(crate) struct AccountOverviewTemplate<'a> {
    pub(crate) overview: &'a crate::account_home::AccountOverviewView,
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
#[template(path = "organization-network-policies.html")]
pub(crate) struct NetworkPoliciesTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a crate::routes::network_policies::ListPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "organization-network-policy.html")]
pub(crate) struct NetworkPolicyTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a crate::routes::network_policies::PolicyPageView,
    pub(crate) active_tab: &'static str,
}

#[derive(Template)]
#[template(path = "hosts.html")]
pub(crate) struct HostsTemplate<'a> {
    pub(crate) view: &'a DashboardView,
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) hosts: Vec<crate::hosts_connect::HostRow>,
    /// Why the hosts could not be read; empty when they were.
    pub(crate) error: String,
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

/// One row of the Sandboxes list, for a live update of that row (#4762).
#[derive(Template)]
#[template(path = "environment-row.html")]
pub(crate) struct EnvironmentRowTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) page: &'a EnvironmentsPageView,
    pub(crate) sandbox: &'a EnvironmentRow,
}

/// The billing banner fragment: one `.cw-banner`, or a hidden placeholder.
/// Either re-fetches itself when the organization's credit changes or the
/// live stream resyncs (#4762), so a banner appears and goes without a
/// reload.
#[derive(Template)]
#[template(path = "billing-banner.html")]
pub(crate) struct BillingBannerTemplate<'a> {
    pub(crate) banner: Option<BillingBannerView>,
    pub(crate) slug: &'a str,
}

/// The Billing page's live part, which its fragment re-renders.
#[derive(Template)]
#[template(path = "organization-billing-stack.html")]
pub(crate) struct BillingStackTemplate<'a> {
    pub(crate) organization: &'a OrganizationContext,
    pub(crate) billing: &'a BillingPageView,
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
    /// A Retry setup was refused until its reclone is confirmed, so the page
    /// opens that confirmation (#4767).
    pub(crate) confirm_reclone: bool,
    /// When a Retry setup that started was asked for, so the step list
    /// follows it (#4767); empty otherwise.
    pub(crate) setup_retry_since: String,
}

impl<'a> TerminalTemplate<'a> {
    pub(crate) fn new(
        view: &'a DashboardView,
        organization: &'a OrganizationContext,
        page: &'a TerminalPageView,
        csrf_token: &'a str,
        style_nonce: &'a str,
    ) -> Self {
        Self {
            view,
            organization,
            page,
            csrf_token,
            style_nonce,
            confirm_reclone: false,
            setup_retry_since: String::new(),
        }
    }

    /// A page as a test renders it, with a fixed token and nonce.
    #[cfg(test)]
    pub(crate) fn for_test(
        view: &'a DashboardView,
        organization: &'a OrganizationContext,
        page: &'a TerminalPageView,
    ) -> Self {
        Self::new(view, organization, page, "csrf", "nonce")
    }
}

impl TerminalTemplate<'_> {
    /// When this page was rendered, by the server's clock. A starting page's
    /// setup stream skips only a run that ended before it (#3772).
    pub(crate) fn rendered_at(&self) -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
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
