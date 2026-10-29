use std::{collections::HashSet, time::Duration};

use axum::http::HeaderValue;
use codewire_admin_proto::codewire::admin::v1::{
    AdjustOrganizationCreditRequest, AdminServiceClient, BillingCatalogServiceClient,
    ClearOrganizationEnvironmentQuotaRequest, CreatePlanRequest, CreatePriceRequest,
    EnvironmentQuota, GetCatalogRequest, GetDefaultEnvironmentQuotaRequest,
    GetOrganizationOverviewRequest, GetStatsRequest, ListAuditLogsRequest,
    ListConfidentialOrganizationsRequest, ListOrganizationsRequest,
    ListSubscriptionMigrationsRequest, PlanSpec, PreviewSubscriptionMigrationRequest,
    RunSubscriptionMigrationRequest, SetDefaultEnvironmentQuotaRequest,
    SetOrganizationConfidentialEnvironmentsRequest, SetOrganizationEnvironmentQuotaRequest,
    SetOrganizationRateCardRequest, SetPlanArchivedRequest, SetPriceArchivedRequest,
    UpdatePlanRequest, UpdatePriceRequest, UpdateSettingRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{state::AppState, time_display::calendar_datetime, transport::BrowserTransport};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct AdminStatsView {
    pub(crate) total_environments: String,
    pub(crate) active_environments: String,
    pub(crate) monthly_cost: String,
    pub(crate) monthly_cpu_hours: String,
    pub(crate) monthly_memory_hours: String,
}

#[derive(Debug)]
pub(crate) struct AuditLogRow {
    pub(crate) occurred: String,
    pub(crate) action: String,
    pub(crate) user: String,
    pub(crate) ip_address: String,
    pub(crate) severity: String,
    pub(crate) severity_tone: &'static str,
    pub(crate) metadata: String,
    pub(crate) has_metadata: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CatalogPlanView {
    pub(crate) resource_type: String,
    pub(crate) plan_key: String,
    pub(crate) display_name: String,
    pub(crate) price_cents: i32,
    pub(crate) included_devs: i32,
    pub(crate) max_concurrent_ws: i32,
    pub(crate) max_team_members: i32,
    pub(crate) storage_gb: i32,
    pub(crate) is_contact_us: bool,
    pub(crate) is_admin_only: bool,
    pub(crate) included_cpu_hours: i32,
    pub(crate) included_mem_gb_hours: i32,
    pub(crate) included_disk_gb_hours: i32,
    pub(crate) cpu_overage_cents: f64,
    pub(crate) mem_overage_cents: f64,
    pub(crate) disk_overage_cents: f64,
    pub(crate) archived: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CatalogPriceView {
    pub(crate) resource_type: String,
    pub(crate) plan_key: String,
    pub(crate) stripe_mode: String,
    pub(crate) price_kind: String,
    pub(crate) stripe_price_id: String,
    pub(crate) archived: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CatalogSettingView {
    pub(crate) setting_key: String,
    pub(crate) int_value: i32,
}

#[derive(Debug)]
pub(crate) struct MigrationRunView {
    pub(crate) occurred: String,
    pub(crate) resource_type: String,
    pub(crate) source_plan_key: String,
    pub(crate) target_plan_key: String,
    pub(crate) proration_behavior: String,
    pub(crate) migrated_count: i32,
    pub(crate) skipped_count: i32,
    pub(crate) failed_count: i32,
    pub(crate) created_by: String,
}

#[derive(Debug)]
pub(crate) struct MigrationSampleView {
    pub(crate) scope: String,
    pub(crate) org_slug: String,
    pub(crate) subscription_id: String,
    pub(crate) status: String,
    pub(crate) current_plan_key: String,
    pub(crate) current_price_id: String,
}

#[derive(Debug)]
pub(crate) struct MigrationPreviewView {
    pub(crate) available: bool,
    pub(crate) resource_type: String,
    pub(crate) source_plan_key: String,
    pub(crate) target_plan_key: String,
    pub(crate) target_price_id: String,
    pub(crate) matching_count: i32,
    pub(crate) candidate_count: i32,
    pub(crate) already_on_target: i32,
    pub(crate) samples: Vec<MigrationSampleView>,
}

impl Default for MigrationPreviewView {
    fn default() -> Self {
        Self {
            available: false,
            resource_type: "org".to_owned(),
            source_plan_key: String::new(),
            target_plan_key: String::new(),
            target_price_id: String::new(),
            matching_count: 0,
            candidate_count: 0,
            already_on_target: 0,
            samples: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AdminCatalogView {
    pub(crate) plans: Vec<CatalogPlanView>,
    pub(crate) prices: Vec<CatalogPriceView>,
    pub(crate) settings: Vec<CatalogSettingView>,
    pub(crate) migrations: Vec<MigrationRunView>,
    pub(crate) preview: MigrationPreviewView,
    pub(crate) csrf_token: String,
    pub(crate) message: String,
    pub(crate) error: String,
}

#[derive(Debug)]
pub(crate) struct AdminOrganizationRow {
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) billing_plan: String,
    pub(crate) billing_status: String,
    pub(crate) created: String,
    pub(crate) url: String,
    /// Opted in to confidential environments (#2497); `None` while the
    /// billing service that owns the opt-in cannot be read.
    pub(crate) confidential_environments: Option<bool>,
}

#[derive(Debug)]
pub(crate) struct AdminMemberRow {
    pub(crate) email: String,
    pub(crate) role: String,
    pub(crate) joined: String,
}

#[derive(Debug)]
pub(crate) struct AdminSubscriptionRow {
    pub(crate) kind: String,
    pub(crate) plan: String,
    pub(crate) status: String,
    pub(crate) updated: String,
}

#[derive(Debug)]
pub(crate) struct AdminApiKeyRow {
    pub(crate) name: String,
    pub(crate) created: String,
    pub(crate) last_used: String,
    pub(crate) expires: String,
    pub(crate) disabled: bool,
}

/// One limit as the page shows it: the raw value for the form and a
/// readable one ("Unlimited", "32 vCPU").
#[derive(Debug, Clone, Default)]
pub(crate) struct QuotaLimitView {
    pub(crate) value: i32,
    pub(crate) display: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct QuotaView {
    pub(crate) environments: QuotaLimitView,
    pub(crate) sandboxes: QuotaLimitView,
    pub(crate) cpu_millicores: QuotaLimitView,
    pub(crate) memory_mb: QuotaLimitView,
}

/// One rate card an administrator can choose (#3381).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RateCardOption {
    pub(crate) value: &'static str,
    pub(crate) label: &'static str,
    pub(crate) selected: bool,
}

/// The rate cards, in the order the page offers them.
pub(crate) const RATE_CARDS: [(&str, &str); 3] = [
    ("regular", "Regular"),
    ("discounted", "Discounted"),
    ("unlimited", "Unlimited"),
];

/// One credit ledger entry as the page shows it.
#[derive(Debug)]
pub(crate) struct AdminCreditRow {
    pub(crate) kind: String,
    pub(crate) amount: String,
    pub(crate) when: String,
    pub(crate) note: String,
}

#[derive(Debug, Default)]
pub(crate) struct AdminOrganizationView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) created: String,
    pub(crate) members: Vec<AdminMemberRow>,
    pub(crate) billing_plan: String,
    pub(crate) billing_status: String,
    pub(crate) billing_exempt: bool,
    pub(crate) effective_plan: String,
    pub(crate) subscriptions: Vec<AdminSubscriptionRow>,
    /// The card's name, as the page shows it.
    pub(crate) rate_card: String,
    pub(crate) rate_cards: Vec<RateCardOption>,
    /// Signed, in euros.
    pub(crate) credit_balance: String,
    pub(crate) credit_negative: bool,
    pub(crate) credit_entries: Vec<AdminCreditRow>,
    pub(crate) has_explicit_quota: bool,
    pub(crate) effective_quota: QuotaView,
    /// Opted in to confidential environments (#2497); `None` while the
    /// billing service that owns the opt-in cannot be read.
    pub(crate) confidential_environments: Option<bool>,
    pub(crate) active_environments: i64,
    pub(crate) active_sandboxes: i64,
    pub(crate) used_cpu: String,
    pub(crate) used_memory: String,
    pub(crate) api_keys: Vec<AdminApiKeyRow>,
}

/// The four limits an operator submits; each -1 (unlimited) or positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotaMutation {
    pub(crate) environments: i32,
    pub(crate) sandboxes: i32,
    pub(crate) cpu_millicores: i32,
    pub(crate) memory_mb: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct PlanMutation {
    pub(crate) resource_type: String,
    pub(crate) plan_key: String,
    pub(crate) plan: CatalogPlanView,
}

#[derive(Clone, Debug)]
pub(crate) struct PriceMutation {
    pub(crate) resource_type: String,
    pub(crate) plan_key: String,
    pub(crate) stripe_mode: String,
    pub(crate) price_kind: String,
    pub(crate) stripe_price_id: String,
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn admin_client(state: &AppState, cookie: HeaderValue) -> AdminServiceClient<BrowserTransport> {
    AdminServiceClient::new(
        transport(state, cookie),
        ClientConfig::new(state.api_origin.clone()).with_default_timeout(CLIENT_TIMEOUT),
    )
}

fn catalog_client(
    state: &AppState,
    cookie: HeaderValue,
) -> BillingCatalogServiceClient<BrowserTransport> {
    BillingCatalogServiceClient::new(
        transport(state, cookie),
        ClientConfig::new(state.billing_origin.clone()).with_default_timeout(CLIENT_TIMEOUT),
    )
}

pub(crate) async fn stats(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<AdminStatsView, ConnectError> {
    let stats = admin_client(state, cookie)
        .get_stats(GetStatsRequest::default())
        .await?
        .into_owned();
    Ok(AdminStatsView {
        total_environments: stats.total_environments.to_string(),
        active_environments: stats.active_environments.to_string(),
        monthly_cost: money(stats.monthly_cost_cents),
        monthly_cpu_hours: format!("{:.1}", stats.monthly_cpu_hours),
        monthly_memory_hours: format!("{:.1}", stats.monthly_memory_gb_hours),
    })
}

pub(crate) async fn audit_logs(
    state: &AppState,
    cookie: HeaderValue,
    offset: i32,
    action: String,
    severity: String,
) -> Result<Vec<AuditLogRow>, ConnectError> {
    let response = admin_client(state, cookie)
        .list_audit_logs(ListAuditLogsRequest {
            limit: 50,
            offset,
            action,
            severity,
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(response
        .audit_logs
        .into_iter()
        .map(|entry| {
            let metadata = entry
                .metadata
                .into_option()
                .map(|value| bounded(format!("{value:?}"), 4_096))
                .unwrap_or_default();
            AuditLogRow {
                occurred: entry
                    .timestamp
                    .into_option()
                    .map(|value| calendar_datetime(value.seconds))
                    .unwrap_or_else(|| "Unknown time".to_owned()),
                action: entry.action,
                user: entry.user_email.unwrap_or_else(|| "—".to_owned()),
                ip_address: entry.ip_address.unwrap_or_else(|| "—".to_owned()),
                severity_tone: severity_tone(&entry.severity),
                severity: entry.severity,
                has_metadata: !metadata.is_empty(),
                metadata,
            }
        })
        .collect())
}

pub(crate) async fn catalog(
    state: &AppState,
    cookie: HeaderValue,
    csrf_token: String,
    message: String,
    error: String,
) -> Result<AdminCatalogView, ConnectError> {
    let catalog_rpc = catalog_client(state, cookie.clone());
    let migrations_rpc = catalog_client(state, cookie);
    let (catalog, migrations) = tokio::join!(
        catalog_rpc.get_catalog(GetCatalogRequest::default()),
        migrations_rpc.list_subscription_migrations(ListSubscriptionMigrationsRequest {
            limit: 25,
            ..Default::default()
        }),
    );
    let catalog = catalog?.into_owned();
    let migrations = migrations?.into_owned();
    Ok(AdminCatalogView {
        plans: catalog.plans.into_iter().map(plan_view).collect(),
        prices: catalog
            .prices
            .into_iter()
            .map(|price| CatalogPriceView {
                resource_type: price.resource_type,
                plan_key: price.plan_key,
                stripe_mode: price.stripe_mode,
                price_kind: price.price_kind,
                stripe_price_id: price.stripe_price_id,
                archived: price.archived,
            })
            .collect(),
        settings: catalog
            .settings
            .into_iter()
            .map(|setting| CatalogSettingView {
                setting_key: setting.setting_key,
                int_value: setting.int_value,
            })
            .collect(),
        migrations: migrations
            .migrations
            .into_iter()
            .map(migration_view)
            .collect(),
        preview: MigrationPreviewView::default(),
        csrf_token,
        message,
        error,
    })
}

pub(crate) async fn create_plan(
    state: &AppState,
    cookie: HeaderValue,
    mutation: PlanMutation,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .create_plan(CreatePlanRequest {
            resource_type: mutation.resource_type,
            plan_key: mutation.plan_key,
            plan: Some(plan_spec(mutation.plan)).into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_plan(
    state: &AppState,
    cookie: HeaderValue,
    mutation: PlanMutation,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .update_plan(UpdatePlanRequest {
            resource_type: mutation.resource_type,
            plan_key: mutation.plan_key,
            plan: Some(plan_spec(mutation.plan)).into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn set_plan_archived(
    state: &AppState,
    cookie: HeaderValue,
    resource_type: String,
    plan_key: String,
    archived: bool,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .set_plan_archived(SetPlanArchivedRequest {
            resource_type,
            plan_key,
            archived,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn create_price(
    state: &AppState,
    cookie: HeaderValue,
    mutation: PriceMutation,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .create_price(CreatePriceRequest {
            resource_type: mutation.resource_type,
            plan_key: mutation.plan_key,
            stripe_mode: mutation.stripe_mode,
            price_kind: mutation.price_kind,
            stripe_price_id: mutation.stripe_price_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_price(
    state: &AppState,
    cookie: HeaderValue,
    mutation: PriceMutation,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .update_price(UpdatePriceRequest {
            resource_type: mutation.resource_type,
            plan_key: mutation.plan_key,
            stripe_mode: mutation.stripe_mode,
            price_kind: mutation.price_kind,
            stripe_price_id: mutation.stripe_price_id,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn set_price_archived(
    state: &AppState,
    cookie: HeaderValue,
    mutation: PriceMutation,
    archived: bool,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .set_price_archived(SetPriceArchivedRequest {
            resource_type: mutation.resource_type,
            plan_key: mutation.plan_key,
            stripe_mode: mutation.stripe_mode,
            price_kind: mutation.price_kind,
            archived,
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn update_setting(
    state: &AppState,
    cookie: HeaderValue,
    setting_key: String,
    int_value: i32,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .update_setting(UpdateSettingRequest {
            setting_key,
            int_value,
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// Opt an organization in to, or out of, confidential environments. The
/// billing service checks the global administrator and writes the audit
/// event.
pub(crate) async fn set_confidential_environments(
    state: &AppState,
    cookie: HeaderValue,
    organization_slug: String,
    enabled: bool,
) -> Result<(), ConnectError> {
    catalog_client(state, cookie)
        .set_organization_confidential_environments(
            SetOrganizationConfidentialEnvironmentsRequest {
                organization_slug,
                enabled,
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

pub(crate) async fn preview_migration(
    state: &AppState,
    cookie: HeaderValue,
    resource_type: String,
    source_plan_key: String,
    target_plan_key: String,
) -> Result<MigrationPreviewView, ConnectError> {
    let preview = catalog_client(state, cookie)
        .preview_subscription_migration(PreviewSubscriptionMigrationRequest {
            resource_type,
            source_plan_key,
            target_plan_key,
            sample_limit: 8,
            ..Default::default()
        })
        .await?
        .into_owned();
    Ok(MigrationPreviewView {
        available: true,
        resource_type: preview.resource_type,
        source_plan_key: preview.source_plan_key,
        target_plan_key: preview.target_plan_key,
        target_price_id: preview.target_stripe_price_id,
        matching_count: preview.matching_count,
        candidate_count: preview.candidate_count,
        already_on_target: preview.already_on_target,
        samples: preview
            .samples
            .into_iter()
            .map(|sample| MigrationSampleView {
                scope: sample.scope,
                org_slug: sample.org_slug,
                subscription_id: sample.stripe_subscription_id,
                status: sample.status,
                current_plan_key: sample.current_plan_key,
                current_price_id: sample.current_stripe_price_id.unwrap_or_default(),
            })
            .collect(),
    })
}

pub(crate) async fn run_migration(
    state: &AppState,
    cookie: HeaderValue,
    resource_type: String,
    source_plan_key: String,
    target_plan_key: String,
    proration_behavior: String,
) -> Result<MigrationRunView, ConnectError> {
    let response = catalog_client(state, cookie)
        .run_subscription_migration(RunSubscriptionMigrationRequest {
            resource_type,
            source_plan_key,
            target_plan_key,
            proration_behavior,
            ..Default::default()
        })
        .await?
        .into_owned();
    response
        .migration
        .into_option()
        .map(migration_view)
        .ok_or_else(|| ConnectError::internal("migration result missing"))
}

/// The ids of the organizations opted in to confidential environments, from
/// the billing service that owns the opt-in (#2497). `None` when billing
/// cannot answer, so the Organizations pages still render without it.
async fn confidential_organization_ids(
    state: &AppState,
    cookie: HeaderValue,
) -> Option<HashSet<String>> {
    let response = catalog_client(state, cookie)
        .list_confidential_organizations(ListConfidentialOrganizationsRequest::default())
        .await
        .ok()?
        .into_owned();
    Some(
        response
            .organizations
            .into_iter()
            .map(|organization| organization.organization_id)
            .collect(),
    )
}

pub(crate) async fn organizations(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<AdminOrganizationRow>, ConnectError> {
    let admin_rpc = admin_client(state, cookie.clone());
    let (response, confidential) = tokio::join!(
        admin_rpc.list_organizations(ListOrganizationsRequest::default()),
        confidential_organization_ids(state, cookie),
    );
    let response = response?.into_owned();
    Ok(response
        .organizations
        .into_iter()
        .map(|organization| AdminOrganizationRow {
            confidential_environments: confidential
                .as_ref()
                .map(|ids| ids.contains(&organization.id)),
            url: format!("/admin/organizations/{}/", organization.id),
            name: organization.name,
            slug: organization.slug,
            billing_plan: organization.billing_plan,
            billing_status: organization.billing_status,
            created: timestamp_text(
                organization
                    .created_at
                    .into_option()
                    .map(|value| value.seconds),
            ),
        })
        .collect())
}

pub(crate) async fn organization(
    state: &AppState,
    cookie: HeaderValue,
    organization_id: &str,
) -> Result<AdminOrganizationView, ConnectError> {
    let admin_rpc = admin_client(state, cookie.clone());
    let (response, confidential) = tokio::join!(
        admin_rpc.get_organization_overview(GetOrganizationOverviewRequest {
            organization_id: organization_id.to_owned(),
            ..Default::default()
        }),
        confidential_organization_ids(state, cookie),
    );
    let response = response?.into_owned();
    let organization = response.organization.into_option().unwrap_or_default();
    let billing = response.billing.into_option().unwrap_or_default();
    let quota = response.quota.into_option().unwrap_or_default();
    let usage = response.usage.into_option().unwrap_or_default();
    Ok(AdminOrganizationView {
        confidential_environments: confidential
            .as_ref()
            .map(|ids| ids.contains(&organization.id)),
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        created: timestamp_text(
            organization
                .created_at
                .into_option()
                .map(|value| value.seconds),
        ),
        members: response
            .members
            .into_iter()
            .map(|member| AdminMemberRow {
                email: if member.email.is_empty() {
                    member.user_id
                } else {
                    member.email
                },
                role: member.role,
                joined: timestamp_text(member.joined_at.into_option().map(|value| value.seconds)),
            })
            .collect(),
        billing_plan: billing.billing_plan,
        billing_status: billing.billing_status,
        billing_exempt: billing.billing_exempt,
        effective_plan: if billing.effective_plan.is_empty() {
            "None".to_owned()
        } else {
            billing.effective_plan
        },
        rate_card: RATE_CARDS
            .iter()
            .find(|(value, _)| *value == billing.rate_card)
            .map_or_else(
                || billing.rate_card.clone(),
                |(_, label)| (*label).to_owned(),
            ),
        rate_cards: RATE_CARDS
            .iter()
            .map(|(value, label)| RateCardOption {
                value,
                label,
                selected: *value == billing.rate_card,
            })
            .collect(),
        credit_balance: euro_text(billing.credit_balance_nano_eur),
        credit_negative: billing.credit_balance_nano_eur < 0,
        credit_entries: billing
            .recent_credit
            .into_iter()
            .map(|entry| AdminCreditRow {
                kind: credit_kind_text(&entry.kind).to_owned(),
                amount: euro_text(entry.amount_nano_eur),
                when: timestamp_text(entry.created_at.into_option().map(|value| value.seconds)),
                note: entry.reason,
            })
            .collect(),
        subscriptions: billing
            .subscriptions
            .into_iter()
            .map(|subscription| AdminSubscriptionRow {
                kind: subscription.kind,
                plan: subscription.plan,
                status: subscription.status,
                updated: timestamp_text(
                    subscription
                        .updated_at
                        .into_option()
                        .map(|value| value.seconds),
                ),
            })
            .collect(),
        has_explicit_quota: quota.explicit.is_set(),
        effective_quota: quota_view(quota.effective.into_option().unwrap_or_default()),
        active_environments: usage.active_environments,
        active_sandboxes: usage.active_sandboxes,
        used_cpu: cpu_text(usage.cpu_millicores),
        used_memory: memory_text(usage.memory_mb),
        api_keys: response
            .api_keys
            .into_iter()
            .map(|key| AdminApiKeyRow {
                name: key.name,
                created: timestamp_text(key.created_at.into_option().map(|value| value.seconds)),
                last_used: key
                    .last_used_at
                    .into_option()
                    .map(|value| calendar_datetime(value.seconds))
                    .unwrap_or_else(|| "Never".to_owned()),
                expires: key
                    .expires_at
                    .into_option()
                    .map(|value| calendar_datetime(value.seconds))
                    .unwrap_or_else(|| "Never".to_owned()),
                disabled: key.disabled,
            })
            .collect(),
    })
}

pub(crate) async fn set_organization_rate_card(
    state: &AppState,
    cookie: HeaderValue,
    organization_id: &str,
    rate_card: &str,
) -> Result<(), ConnectError> {
    admin_client(state, cookie)
        .set_organization_rate_card(SetOrganizationRateCardRequest {
            organization_id: organization_id.to_owned(),
            rate_card: rate_card.to_owned(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn adjust_organization_credit(
    state: &AppState,
    cookie: HeaderValue,
    organization_id: &str,
    amount_nano_eur: i64,
    reason: &str,
    idempotency_key: &str,
) -> Result<(), ConnectError> {
    admin_client(state, cookie)
        .adjust_organization_credit(AdjustOrganizationCreditRequest {
            organization_id: organization_id.to_owned(),
            amount_nano_eur,
            reason: reason.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub(crate) async fn set_organization_quota(
    state: &AppState,
    cookie: HeaderValue,
    organization_id: &str,
    quota: QuotaMutation,
) -> Result<(), ConnectError> {
    admin_client(state, cookie)
        .set_organization_environment_quota(SetOrganizationEnvironmentQuotaRequest {
            organization_id: organization_id.to_owned(),
            quota: Some(quota_message(quota)).into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

/// The defaults for organizations without their own quota.
pub(crate) async fn default_quota(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<QuotaView, ConnectError> {
    let response = admin_client(state, cookie)
        .get_default_environment_quota(GetDefaultEnvironmentQuotaRequest::default())
        .await?
        .into_owned();
    Ok(quota_view(response.quota.into_option().unwrap_or_default()))
}

pub(crate) async fn set_default_quota(
    state: &AppState,
    cookie: HeaderValue,
    quota: QuotaMutation,
) -> Result<(), ConnectError> {
    admin_client(state, cookie)
        .set_default_environment_quota(SetDefaultEnvironmentQuotaRequest {
            quota: Some(quota_message(quota)).into(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn quota_message(quota: QuotaMutation) -> EnvironmentQuota {
    EnvironmentQuota {
        max_concurrent_environments: quota.environments,
        max_concurrent_sandbox: quota.sandboxes,
        max_cpu_millicores: quota.cpu_millicores,
        max_memory_mb: quota.memory_mb,
        ..Default::default()
    }
}

pub(crate) async fn clear_organization_quota(
    state: &AppState,
    cookie: HeaderValue,
    organization_id: &str,
) -> Result<(), ConnectError> {
    admin_client(state, cookie)
        .clear_organization_environment_quota(ClearOrganizationEnvironmentQuotaRequest {
            organization_id: organization_id.to_owned(),
            ..Default::default()
        })
        .await?;
    Ok(())
}

fn timestamp_text(seconds: Option<i64>) -> String {
    seconds
        .map(calendar_datetime)
        .unwrap_or_else(|| "Unknown time".to_owned())
}

fn quota_view(quota: EnvironmentQuota) -> QuotaView {
    QuotaView {
        environments: limit(quota.max_concurrent_environments, |value| value.to_string()),
        sandboxes: limit(quota.max_concurrent_sandbox, |value| value.to_string()),
        cpu_millicores: limit(quota.max_cpu_millicores, |value| cpu_text(i64::from(value))),
        memory_mb: limit(quota.max_memory_mb, |value| memory_text(i64::from(value))),
    }
}

const NANO_EUR_PER_CENT: i64 = 10_000_000;
const NANO_EUR_PER_EURO: i64 = 1_000_000_000;

/// A nano-euro amount in euros: two decimals, or up to six when the amount
/// has more (a minute of usage is a fraction of a cent), never rounded up.
pub(crate) fn euro_text(nano_eur: i64) -> String {
    let sign = if nano_eur < 0 { "-" } else { "" };
    let magnitude = nano_eur.unsigned_abs();
    let whole = magnitude / NANO_EUR_PER_EURO as u64;
    let fraction = format!("{:09}", magnitude % NANO_EUR_PER_EURO as u64);
    let fraction = fraction[..6].trim_end_matches('0');
    let fraction = format!("{fraction:0<2}");
    format!("{sign}€{whole}.{fraction}")
}

/// An administrator's euro amount ("25", "-10.5", "+0.01") in nano-euros:
/// at most two decimals, non-zero, and at most EUR 100,000 either way.
pub(crate) fn euro_amount_nano(text: &str) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    if whole.is_empty()
        || whole.len() > 6
        || fraction.len() > 2
        || (digits.contains('.') && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let cents = whole.parse::<i64>().ok()? * 100 + format!("{fraction:0<2}").parse::<i64>().ok()?;
    if cents == 0 || cents > 100_000 * 100 {
        return None;
    }
    let nano = cents * NANO_EUR_PER_CENT;
    Some(if negative { -nano } else { nano })
}

fn credit_kind_text(kind: &str) -> &'static str {
    match kind {
        "grant" => "Card grant",
        "usage" => "Usage",
        "top_up" => "Top-up",
        "adjustment" => "Adjustment",
        _ => "Other",
    }
}

fn limit(value: i32, display: impl Fn(i32) -> String) -> QuotaLimitView {
    QuotaLimitView {
        value,
        display: if value == -1 {
            "Unlimited".to_owned()
        } else {
            display(value)
        },
    }
}

fn cpu_text(millicores: i64) -> String {
    if millicores % 1000 == 0 {
        format!("{} vCPU", millicores / 1000)
    } else {
        format!("{:.2} vCPU", millicores as f64 / 1000.0)
    }
}

fn memory_text(mebibytes: i64) -> String {
    if mebibytes % 1024 == 0 {
        format!("{} GiB", mebibytes / 1024)
    } else {
        format!("{:.1} GiB", mebibytes as f64 / 1024.0)
    }
}

fn plan_view(plan: codewire_admin_proto::codewire::admin::v1::CatalogPlan) -> CatalogPlanView {
    let spec = plan.plan.into_option().unwrap_or_default();
    CatalogPlanView {
        resource_type: plan.resource_type,
        plan_key: plan.plan_key,
        display_name: spec.display_name,
        price_cents: spec.price_cents,
        included_devs: spec.included_devs,
        max_concurrent_ws: spec.max_concurrent_ws,
        max_team_members: spec.max_team_members,
        storage_gb: spec.storage_gb,
        is_contact_us: spec.is_contact_us,
        is_admin_only: spec.is_admin_only,
        included_cpu_hours: spec.included_cpu_hours,
        included_mem_gb_hours: spec.included_mem_gb_hours,
        included_disk_gb_hours: spec.included_disk_gb_hours,
        cpu_overage_cents: spec.cpu_overage_cents,
        mem_overage_cents: spec.mem_overage_cents,
        disk_overage_cents: spec.disk_overage_cents,
        archived: plan.archived,
    }
}

fn plan_spec(plan: CatalogPlanView) -> PlanSpec {
    PlanSpec {
        display_name: plan.display_name,
        price_cents: plan.price_cents,
        included_devs: plan.included_devs,
        max_concurrent_ws: plan.max_concurrent_ws,
        max_team_members: plan.max_team_members,
        storage_gb: plan.storage_gb,
        is_contact_us: plan.is_contact_us,
        is_admin_only: plan.is_admin_only,
        included_cpu_hours: plan.included_cpu_hours,
        included_mem_gb_hours: plan.included_mem_gb_hours,
        included_disk_gb_hours: plan.included_disk_gb_hours,
        cpu_overage_cents: plan.cpu_overage_cents,
        mem_overage_cents: plan.mem_overage_cents,
        disk_overage_cents: plan.disk_overage_cents,
        ..Default::default()
    }
}

fn migration_view(
    run: codewire_admin_proto::codewire::admin::v1::MigrationRun,
) -> MigrationRunView {
    MigrationRunView {
        occurred: run
            .created_at
            .into_option()
            .map(|value| calendar_datetime(value.seconds))
            .unwrap_or_else(|| "Unknown time".to_owned()),
        resource_type: run.resource_type,
        source_plan_key: run.source_plan_key,
        target_plan_key: run.target_plan_key,
        proration_behavior: run.proration_behavior,
        migrated_count: run.migrated_count,
        skipped_count: run.skipped_count,
        failed_count: run.failed_count,
        created_by: run.created_by.unwrap_or_else(|| "—".to_owned()),
    }
}

fn money(cents: i64) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let absolute = cents.unsigned_abs();
    format!("{sign}${}.{:02}", absolute / 100, absolute % 100)
}

fn bounded(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push('…');
    value
}

fn severity_tone(severity: &str) -> &'static str {
    match severity {
        "error" => "danger",
        "warn" => "warning",
        _ => "muted",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn euro_amounts_round_trip_as_operators_write_them() {
        use super::{euro_amount_nano, euro_text};
        assert_eq!(euro_text(50_000_000_000), "€50.00");
        assert_eq!(euro_text(-1_500_000_000), "-€1.50");
        assert_eq!(euro_text(0), "€0.00");
        // A minute of the default sandbox is a fraction of a cent.
        assert_eq!(euro_text(-3_385_000), "-€0.003385");
        assert_eq!(euro_text(-3_385_999), "-€0.003385");
        assert_eq!(euro_amount_nano("25"), Some(25_000_000_000));
        assert_eq!(euro_amount_nano(" -10.5 "), Some(-10_500_000_000));
        assert_eq!(euro_amount_nano("+0.01"), Some(10_000_000));
        assert_eq!(euro_amount_nano("100000"), Some(100_000_000_000_000));
        for invalid in [
            "",
            "-",
            "0",
            "0.00",
            "1.",
            ".5",
            "1.234",
            "100000.01",
            "1e3",
            "1,5",
            "--1",
            "abc",
            "9999999",
        ] {
            assert_eq!(euro_amount_nano(invalid), None, "{invalid:?}");
        }
    }

    use super::*;

    #[test]
    fn admin_display_values_are_bounded_and_safe() {
        assert_eq!(money(1234), "$12.34");
        assert_eq!(money(-5), "-$0.05");
        assert!(bounded("é".repeat(3_000), 4_096).len() <= 4_099);
        assert_eq!(severity_tone("error"), "danger");
        assert_eq!(severity_tone("unknown"), "muted");
    }

    #[test]
    fn quota_limits_read_as_operators_count_them() {
        let view = quota_view(EnvironmentQuota {
            max_concurrent_environments: -1,
            max_concurrent_sandbox: 50,
            max_cpu_millicores: 32_000,
            max_memory_mb: 65_536,
            ..Default::default()
        });
        assert_eq!(view.environments.display, "Unlimited");
        assert_eq!(view.environments.value, -1);
        assert_eq!(view.sandboxes.display, "50");
        assert_eq!(view.cpu_millicores.display, "32 vCPU");
        assert_eq!(view.memory_mb.display, "64 GiB");
        assert_eq!(cpu_text(2_500), "2.50 vCPU");
        assert_eq!(memory_text(1_536), "1.5 GiB");
    }
}
