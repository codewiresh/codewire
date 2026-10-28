use std::time::Duration;

use axum::http::HeaderValue;
use codewire_admin_proto::codewire::admin::v1::{
    AdminServiceClient, BillingCatalogServiceClient, ClearOrganizationEnvironmentQuotaRequest,
    CreatePlanRequest, CreatePriceRequest, EnvironmentQuota, GetCatalogRequest,
    GetDefaultEnvironmentQuotaRequest, GetOrganizationOverviewRequest, GetStatsRequest,
    ListAuditLogsRequest, ListConfidentialOrganizationsRequest, ListOrganizationsRequest,
    ListSubscriptionMigrationsRequest, PlanSpec, PreviewSubscriptionMigrationRequest,
    RunSubscriptionMigrationRequest, SetDefaultEnvironmentQuotaRequest,
    SetOrganizationConfidentialEnvironmentsRequest, SetOrganizationEnvironmentQuotaRequest,
    SetPlanArchivedRequest, SetPriceArchivedRequest, UpdatePlanRequest, UpdatePriceRequest,
    UpdateSettingRequest,
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

/// An organization opted in to confidential environments.
#[derive(Clone, Debug)]
pub(crate) struct ConfidentialOrganizationView {
    pub(crate) slug: String,
    pub(crate) name: String,
}

#[derive(Debug)]
pub(crate) struct AdminCatalogView {
    pub(crate) plans: Vec<CatalogPlanView>,
    pub(crate) prices: Vec<CatalogPriceView>,
    pub(crate) settings: Vec<CatalogSettingView>,
    pub(crate) migrations: Vec<MigrationRunView>,
    pub(crate) confidential_organizations: Vec<ConfidentialOrganizationView>,
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
    pub(crate) has_explicit_quota: bool,
    pub(crate) effective_quota: QuotaView,
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
    let migrations_rpc = catalog_client(state, cookie.clone());
    let confidential_rpc = catalog_client(state, cookie);
    let (catalog, migrations, confidential) = tokio::join!(
        catalog_rpc.get_catalog(GetCatalogRequest::default()),
        migrations_rpc.list_subscription_migrations(ListSubscriptionMigrationsRequest {
            limit: 25,
            ..Default::default()
        }),
        confidential_rpc
            .list_confidential_organizations(ListConfidentialOrganizationsRequest::default()),
    );
    let catalog = catalog?.into_owned();
    let migrations = migrations?.into_owned();
    let confidential = confidential?.into_owned();
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
        confidential_organizations: confidential
            .organizations
            .into_iter()
            .map(|organization| ConfidentialOrganizationView {
                slug: organization.slug,
                name: organization.name,
            })
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

pub(crate) async fn organizations(
    state: &AppState,
    cookie: HeaderValue,
) -> Result<Vec<AdminOrganizationRow>, ConnectError> {
    let response = admin_client(state, cookie)
        .list_organizations(ListOrganizationsRequest::default())
        .await?
        .into_owned();
    Ok(response
        .organizations
        .into_iter()
        .map(|organization| AdminOrganizationRow {
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
    let response = admin_client(state, cookie)
        .get_organization_overview(GetOrganizationOverviewRequest {
            organization_id: organization_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let organization = response.organization.into_option().unwrap_or_default();
    let billing = response.billing.into_option().unwrap_or_default();
    let quota = response.quota.into_option().unwrap_or_default();
    let usage = response.usage.into_option().unwrap_or_default();
    Ok(AdminOrganizationView {
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
