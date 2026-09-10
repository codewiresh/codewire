use std::time::Duration;

use axum::http::HeaderValue;
use codewire_admin_proto::codewire::admin::v1::{
    AdminServiceClient, BillingCatalogServiceClient, CreatePlanRequest, CreatePriceRequest,
    GetCatalogRequest, GetStatsRequest, ListAuditLogsRequest, ListSubscriptionMigrationsRequest,
    PlanSpec, PreviewSubscriptionMigrationRequest, RunSubscriptionMigrationRequest,
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
}
