use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    admin_connect::{self, CatalogPlanView, PlanMutation, PriceMutation},
    auth::{authenticated_identity, enforce_two_factor},
    error::WebError,
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    routes::{
        dashboard::dashboard_shell_view_from_identity, organization_governance::valid_identifier,
    },
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::{AdminAuditTemplate, AdminBillingTemplate, AdminOverviewTemplate},
    view::DashboardView,
};

const ADMIN_PATH: &str = "/admin/";
const AUDIT_PATH: &str = "/admin/audit/";
const BILLING_PATH: &str = "/admin/billing/";

#[derive(Debug, Default, Deserialize)]
pub(super) struct AdminQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AuditQuery {
    #[serde(default)]
    action: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    offset: i32,
}

#[derive(Debug, Deserialize)]
pub(super) struct PlanSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    resource_type: String,
    plan_key: String,
    display_name: String,
    price_cents: i32,
    included_devs: i32,
    max_concurrent_ws: i32,
    max_team_members: i32,
    storage_gb: i32,
    #[serde(default)]
    is_contact_us: bool,
    #[serde(default)]
    is_admin_only: bool,
    included_cpu_hours: i32,
    included_mem_gb_hours: i32,
    included_disk_gb_hours: i32,
    cpu_overage_cents: f64,
    mem_overage_cents: f64,
    disk_overage_cents: f64,
}

#[derive(Debug, Deserialize)]
pub(super) struct ArchivePlanSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    resource_type: String,
    plan_key: String,
    archived: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct PriceSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    resource_type: String,
    plan_key: String,
    stripe_mode: String,
    price_kind: String,
    stripe_price_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ArchivePriceSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    resource_type: String,
    plan_key: String,
    stripe_mode: String,
    price_kind: String,
    archived: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct SettingSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    setting_key: String,
    int_value: i32,
}

#[derive(Debug, Deserialize)]
pub(super) struct MigrationSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    resource_type: String,
    source_plan_key: String,
    target_plan_key: String,
    #[serde(default = "default_proration")]
    proration_behavior: String,
}

pub(super) async fn overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (dashboard, cookie) = match admin_context(&state, &headers, ADMIN_PATH).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match admin_connect::stats(&state, cookie).await {
        Ok(stats) => render_page(AdminOverviewTemplate {
            view: &dashboard,
            stats: &stats,
        }),
        Err(error) => admin_connect_error(error, ADMIN_PATH, &headers),
    }
}

pub(super) async fn audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Response {
    let (dashboard, cookie) = match admin_context(&state, &headers, AUDIT_PATH).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let query = normalize_audit_query(query);
    let logs = match admin_connect::audit_logs(
        &state,
        cookie,
        query.offset,
        query.action.clone(),
        query.severity.clone(),
    )
    .await
    {
        Ok(logs) => logs,
        Err(error) => return admin_connect_error(error, AUDIT_PATH, &headers),
    };
    let has_previous = query.offset > 0;
    let has_next = logs.len() == 50;
    let previous_url = audit_url(
        query.offset.saturating_sub(50),
        &query.action,
        &query.severity,
    );
    let next_url = audit_url(
        query.offset.saturating_add(50),
        &query.action,
        &query.severity,
    );
    render_page(AdminAuditTemplate {
        view: &dashboard,
        logs: &logs,
        action: &query.action,
        info_selected: query.severity == "info",
        warn_selected: query.severity == "warn",
        error_selected: query.severity == "error",
        has_previous,
        has_next,
        previous_url: &previous_url,
        next_url: &next_url,
    })
}

pub(super) async fn billing(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    let (dashboard, cookie) = match admin_context(&state, &headers, BILLING_PATH).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let token = new_csrf_token();
    let catalog = match admin_connect::catalog(
        &state,
        cookie,
        token.clone(),
        admin_message(&query.message).to_owned(),
        admin_error(&query.error).to_owned(),
    )
    .await
    {
        Ok(catalog) => catalog,
        Err(error) => return admin_connect_error(error, BILLING_PATH, &headers),
    };
    with_csrf_cookie(
        render_page(AdminBillingTemplate {
            view: &dashboard,
            catalog: &catalog,
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn create_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<PlanSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let Some(mutation) = plan_mutation(submission) else {
        return admin_redirect(&state, "", "invalid", &headers);
    };
    mutation_response(
        &state,
        admin_connect::create_plan(&state, cookie, mutation).await,
        "plan-created",
        &headers,
    )
}

pub(super) async fn update_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<PlanSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let Some(mutation) = plan_mutation(submission) else {
        return admin_redirect(&state, "", "invalid", &headers);
    };
    mutation_response(
        &state,
        admin_connect::update_plan(&state, cookie, mutation).await,
        "plan-saved",
        &headers,
    )
}

pub(super) async fn archive_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<ArchivePlanSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.resource_type) || !valid_identifier(&submission.plan_key) {
        return admin_redirect(&state, "", "invalid", &headers);
    }
    mutation_response(
        &state,
        admin_connect::set_plan_archived(
            &state,
            cookie,
            submission.resource_type,
            submission.plan_key,
            submission.archived,
        )
        .await,
        "plan-archived",
        &headers,
    )
}

pub(super) async fn create_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<PriceSubmission>,
) -> Response {
    price_action(&state, &headers, submission, true).await
}

pub(super) async fn update_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<PriceSubmission>,
) -> Response {
    price_action(&state, &headers, submission, false).await
}

pub(super) async fn archive_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<ArchivePriceSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let price = PriceMutation {
        resource_type: submission.resource_type,
        plan_key: submission.plan_key,
        stripe_mode: submission.stripe_mode,
        price_kind: submission.price_kind,
        stripe_price_id: String::new(),
    };
    if !valid_price(&price, false) {
        return admin_redirect(&state, "", "invalid", &headers);
    }
    mutation_response(
        &state,
        admin_connect::set_price_archived(&state, cookie, price, submission.archived).await,
        "price-archived",
        &headers,
    )
}

pub(super) async fn update_setting(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<SettingSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.setting_key) {
        return admin_redirect(&state, "", "invalid", &headers);
    }
    mutation_response(
        &state,
        admin_connect::update_setting(&state, cookie, submission.setting_key, submission.int_value)
            .await,
        "setting-saved",
        &headers,
    )
}

pub(super) async fn preview_migration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<MigrationSubmission>,
) -> Response {
    let (dashboard, cookie) =
        match admin_action_page_context(&state, &headers, &submission.csrf).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !valid_migration(&submission) {
        return admin_redirect(&state, "", "invalid", &headers);
    }
    let mut catalog = match admin_connect::catalog(
        &state,
        cookie.clone(),
        submission.csrf.clone(),
        String::new(),
        String::new(),
    )
    .await
    {
        Ok(catalog) => catalog,
        Err(error) => return admin_connect_error(error, BILLING_PATH, &headers),
    };
    catalog.preview = match admin_connect::preview_migration(
        &state,
        cookie,
        submission.resource_type,
        submission.source_plan_key,
        submission.target_plan_key,
    )
    .await
    {
        Ok(preview) => preview,
        Err(error) => return admin_connect_error(error, BILLING_PATH, &headers),
    };
    catalog.message = "Migration preview updated.".to_owned();
    render_page(AdminBillingTemplate {
        view: &dashboard,
        catalog: &catalog,
    })
}

pub(super) async fn run_migration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(submission): Form<MigrationSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if !valid_migration(&submission) {
        return admin_redirect(&state, "", "invalid", &headers);
    }
    mutation_response(
        &state,
        admin_connect::run_migration(
            &state,
            cookie,
            submission.resource_type,
            submission.source_plan_key,
            submission.target_plan_key,
            submission.proration_behavior,
        )
        .await
        .map(|_| ()),
        "migration-ran",
        &headers,
    )
}

async fn price_action(
    state: &AppState,
    headers: &HeaderMap,
    submission: PriceSubmission,
    create: bool,
) -> Response {
    let cookie = match admin_action_context(state, headers, &submission.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let price = PriceMutation {
        resource_type: submission.resource_type,
        plan_key: submission.plan_key,
        stripe_mode: submission.stripe_mode,
        price_kind: submission.price_kind,
        stripe_price_id: submission.stripe_price_id,
    };
    if !valid_price(&price, true) {
        return admin_redirect(state, "", "invalid", headers);
    }
    let result = if create {
        admin_connect::create_price(state, cookie, price).await
    } else {
        admin_connect::update_price(state, cookie, price).await
    };
    mutation_response(
        state,
        result,
        if create {
            "price-created"
        } else {
            "price-saved"
        },
        headers,
    )
}

async fn admin_context(
    state: &AppState,
    headers: &HeaderMap,
    continuation: &str,
) -> Result<(DashboardView, HeaderValue), Response> {
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| admin_route_error(error, continuation, headers))?;
    enforce_two_factor(&identity)
        .map_err(|error| admin_route_error(error, continuation, headers))?;
    if !identity.is_admin {
        return Err(redirect("/dashboard/".to_owned(), headers));
    }
    let cookie = canonical_cookie(headers).map_err(|()| login_redirect(continuation, headers))?;
    let dashboard = dashboard_shell_view_from_identity(state, &identity, cookie.clone())
        .await
        .map_err(|error| admin_route_error(error, continuation, headers))?;
    Ok((dashboard, cookie))
}

async fn admin_action_context(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<HeaderValue, Response> {
    admin_action_page_context(state, headers, csrf)
        .await
        .map(|(_, cookie)| cookie)
}

async fn admin_action_page_context(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<(DashboardView, HeaderValue), Response> {
    if !request_has_same_origin(headers, &state.public_origin) || !valid_csrf_token(headers, csrf) {
        return Err(error_page(WebError::CsrfRejected));
    }
    admin_context(state, headers, BILLING_PATH).await
}

fn plan_mutation(submission: PlanSubmission) -> Option<PlanMutation> {
    let plan = CatalogPlanView {
        resource_type: submission.resource_type.clone(),
        plan_key: submission.plan_key.clone(),
        display_name: submission.display_name.trim().to_owned(),
        price_cents: submission.price_cents,
        included_devs: submission.included_devs,
        max_concurrent_ws: submission.max_concurrent_ws,
        max_team_members: submission.max_team_members,
        storage_gb: submission.storage_gb,
        is_contact_us: submission.is_contact_us,
        is_admin_only: submission.is_admin_only,
        included_cpu_hours: submission.included_cpu_hours,
        included_mem_gb_hours: submission.included_mem_gb_hours,
        included_disk_gb_hours: submission.included_disk_gb_hours,
        cpu_overage_cents: submission.cpu_overage_cents,
        mem_overage_cents: submission.mem_overage_cents,
        disk_overage_cents: submission.disk_overage_cents,
        archived: false,
    };
    let numbers_are_valid = [
        plan.price_cents,
        plan.included_devs,
        plan.max_concurrent_ws,
        plan.max_team_members,
        plan.storage_gb,
        plan.included_cpu_hours,
        plan.included_mem_gb_hours,
        plan.included_disk_gb_hours,
    ]
    .into_iter()
    .all(|value| value >= 0)
        && [
            plan.cpu_overage_cents,
            plan.mem_overage_cents,
            plan.disk_overage_cents,
        ]
        .into_iter()
        .all(|value| value.is_finite() && value >= 0.0);
    (valid_identifier(&plan.resource_type)
        && valid_identifier(&plan.plan_key)
        && valid_identifier(&plan.display_name)
        && numbers_are_valid)
        .then_some(PlanMutation {
            resource_type: submission.resource_type,
            plan_key: submission.plan_key,
            plan,
        })
}

fn valid_price(price: &PriceMutation, require_id: bool) -> bool {
    valid_identifier(&price.resource_type)
        && valid_identifier(&price.plan_key)
        && matches!(price.stripe_mode.as_str(), "test" | "live")
        && valid_identifier(&price.price_kind)
        && (!require_id || valid_identifier(&price.stripe_price_id))
}

fn valid_migration(submission: &MigrationSubmission) -> bool {
    valid_identifier(&submission.resource_type)
        && valid_identifier(&submission.source_plan_key)
        && valid_identifier(&submission.target_plan_key)
        && matches!(
            submission.proration_behavior.as_str(),
            "none" | "create_prorations" | "always_invoice"
        )
}

fn normalize_audit_query(mut query: AuditQuery) -> AuditQuery {
    query.offset = query.offset.clamp(0, 100_000);
    query.action = query.action.trim().to_owned();
    if !query.action.is_empty() && !valid_identifier(&query.action) {
        query.action.clear();
    }
    if !matches!(query.severity.as_str(), "info" | "warn" | "error") {
        query.severity.clear();
    }
    query
}

fn audit_url(offset: i32, action: &str, severity: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if !action.is_empty() {
        query.append_pair("action", action);
    }
    if !severity.is_empty() {
        query.append_pair("severity", severity);
    }
    if offset > 0 {
        query.append_pair("offset", &offset.to_string());
    }
    let query = query.finish();
    if query.is_empty() {
        AUDIT_PATH.to_owned()
    } else {
        format!("{AUDIT_PATH}?{query}")
    }
}

fn mutation_response(
    state: &AppState,
    result: Result<(), ConnectError>,
    message: &str,
    headers: &HeaderMap,
) -> Response {
    match result {
        Ok(()) => admin_redirect(state, message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(BILLING_PATH, headers)
        }
        Err(error) => admin_redirect(state, "", mutation_error(&error), headers),
    }
}

fn admin_redirect(state: &AppState, message: &str, error: &str, headers: &HeaderMap) -> Response {
    let mut target = BILLING_PATH.to_owned();
    if !message.is_empty() {
        target.push_str("?message=");
        target.push_str(message);
    } else if !error.is_empty() {
        target.push_str("?error=");
        target.push_str(error);
    }
    let token = new_csrf_token();
    with_csrf_cookie(
        redirect(target, headers),
        csrf_cookie(&state.public_origin, &token),
    )
}

fn mutation_error(error: &ConnectError) -> &'static str {
    match error.code {
        ErrorCode::PermissionDenied => "not-authorized",
        ErrorCode::InvalidArgument => "invalid",
        ErrorCode::NotFound => "not-found",
        ErrorCode::AlreadyExists | ErrorCode::Aborted => "conflict",
        _ => "unavailable",
    }
}

fn admin_message(value: &str) -> &'static str {
    match value {
        "plan-created" => "Billing plan created.",
        "plan-saved" => "Billing plan saved.",
        "plan-archived" => "Billing plan archive state updated.",
        "price-created" => "Stripe price created.",
        "price-saved" => "Stripe price saved.",
        "price-archived" => "Stripe price archive state updated.",
        "setting-saved" => "Billing setting saved.",
        "migration-ran" => "Subscription migration completed.",
        _ => "",
    }
}

fn admin_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change the billing catalog.",
        "invalid" => "Review the catalog values and try again.",
        "not-found" => "The catalog record no longer exists.",
        "conflict" => "A conflicting catalog record already exists.",
        "unavailable" => "The billing catalog is temporarily unavailable.",
        _ => "",
    }
}

fn admin_connect_error(error: ConnectError, continuation: &str, headers: &HeaderMap) -> Response {
    match error.code {
        ErrorCode::Unauthenticated => login_redirect(continuation, headers),
        ErrorCode::PermissionDenied => error_page(WebError::Forbidden),
        ErrorCode::NotFound => error_page(WebError::NotFound),
        _ => error_page(WebError::Connect(error)),
    }
}

fn admin_route_error(error: WebError, continuation: &str, headers: &HeaderMap) -> Response {
    match error {
        WebError::Unauthorized => login_redirect(continuation, headers),
        WebError::TwoFactorRequired => two_factor_redirect(continuation, headers),
        error => error_page(error),
    }
}

fn default_proration() -> String {
    "none".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_filters_and_pagination_are_bounded_and_encoded() {
        let query = normalize_audit_query(AuditQuery {
            action: " user.signin ".into(),
            severity: "warn".into(),
            offset: -1,
        });
        assert_eq!(query.action, "user.signin");
        assert_eq!(query.offset, 0);
        assert_eq!(
            audit_url(50, "user sign-in", "warn"),
            "/admin/audit/?action=user+sign-in&severity=warn&offset=50"
        );
        assert!(
            normalize_audit_query(AuditQuery {
                action: "x\ny".into(),
                severity: "fatal".into(),
                offset: i32::MAX
            })
            .action
            .is_empty()
        );
    }

    #[test]
    fn migration_proration_is_an_exact_allowlist() {
        let mut submission = MigrationSubmission {
            csrf: "token".into(),
            resource_type: "org".into(),
            source_plan_key: "old".into(),
            target_plan_key: "new".into(),
            proration_behavior: "none".into(),
        };
        assert!(valid_migration(&submission));
        submission.proration_behavior = "charge_everything".into();
        assert!(!valid_migration(&submission));
    }

    #[test]
    fn admin_feedback_does_not_reflect_query_content() {
        assert_eq!(admin_message("plan-created"), "Billing plan created.");
        assert_eq!(admin_message("<script>"), "");
        assert_eq!(admin_error("raw-upstream-detail"), "");
    }
}
