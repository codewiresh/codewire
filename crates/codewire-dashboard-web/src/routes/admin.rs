use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::{
    admin_connect::{self, CatalogPlanView, PlanMutation, PriceMutation, QuotaMutation},
    auth::{authenticated_identity, enforce_two_factor},
    error::WebError,
    raw_auth::{forward_session_cookies, get_json, post_json},
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    routes::{
        dashboard::{dashboard_shell_view_from_identity, select_shell_organization},
        organization_governance::valid_identifier,
    },
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, page_csrf_token, request_has_same_origin,
        valid_csrf_token, with_csrf_cookie,
    },
    state::AppState,
    templates::{
        AdminAccountsTemplate, AdminAuditTemplate, AdminBillingTemplate, AdminOrganizationTemplate,
        AdminOrganizationsTemplate, AdminOverviewTemplate,
    },
    view::{AccountAccessView, DashboardView},
};

const ADMIN_PATH: &str = "/admin/";
const ACCOUNTS_PATH: &str = "/admin/accounts/";
const AUDIT_PATH: &str = "/admin/audit/";
const BILLING_PATH: &str = "/admin/billing/";
const ORGANIZATIONS_PATH: &str = "/admin/organizations/";

#[derive(Debug, Default, Deserialize)]
pub(super) struct AdminQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AuditQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    offset: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountAccessResponse {
    id: String,
    email: String,
    name: Option<String>,
    email_verified: bool,
    enabled: bool,
    access_reason: Option<String>,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct AccountAccessListResponse {
    accounts: Vec<AccountAccessResponse>,
}

#[derive(Debug, Serialize)]
struct SetAccountEnabledRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct SetAccountEnabledResponse {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct AccountAccessSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    user_id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct QuotaSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    organization_id: String,
    environments: i32,
    sandboxes: i32,
    cpu_millicores: i32,
    memory_mb: i32,
}

#[derive(Debug, Deserialize)]
pub(super) struct DefaultQuotaSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    environments: i32,
    sandboxes: i32,
    cpu_millicores: i32,
    memory_mb: i32,
}

#[derive(Debug, Deserialize)]
pub(super) struct QuotaClearSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    organization_id: String,
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
pub(super) struct ConfidentialOrganizationSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    organization_id: String,
    organization_slug: String,
    enabled: bool,
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

pub(super) async fn overview(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = ADMIN_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    match admin_connect::stats(&state, cookie).await {
        Ok(stats) => render_page(AdminOverviewTemplate {
            view: &dashboard,
            stats: &stats,
        }),
        Err(error) => admin_connect_error(error, &continuation, &headers),
    }
}

pub(super) async fn accounts(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = ACCOUNTS_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let identity =
        match get_json::<AccountAccessListResponse>(&state, "/api/admin/accounts", cookie).await {
            Ok(identity) => identity,
            Err(()) => return error_page(WebError::IdentityUnavailable),
        };
    if identity.status == StatusCode::UNAUTHORIZED {
        return login_redirect(&continuation, &headers);
    }
    if identity.status == StatusCode::FORBIDDEN {
        return error_page(WebError::Forbidden);
    }
    if !identity.status.is_success() {
        return error_page(WebError::IdentityUnavailable);
    }
    let Some(body) = identity.body.as_ref() else {
        return error_page(WebError::IdentityUnavailable);
    };
    let accounts = body
        .accounts
        .iter()
        .map(account_access_view)
        .collect::<Vec<_>>();
    let token = page_csrf_token(&headers);
    let response = with_csrf_cookie(
        render_page(AdminAccountsTemplate {
            view: &dashboard,
            accounts: &accounts,
            csrf_token: &token,
            message: account_message(&query.message),
            error: account_error(&query.error),
        }),
        csrf_cookie(&state.public_origin, &token),
    );
    forward_session_cookies(response, &identity)
}

pub(super) async fn set_account_enabled(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<AccountAccessSubmission>,
) -> Response {
    let cookie = match admin_action_page_context_for(
        &state,
        &headers,
        &submission.csrf,
        &query.org,
        ACCOUNTS_PATH,
    )
    .await
    {
        Ok((_, cookie)) => cookie,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.user_id) {
        return account_redirect(&state, "", "invalid", &headers);
    }
    let path = format!("/api/admin/accounts/{}/enabled", submission.user_id);
    let identity = match post_json::<_, SetAccountEnabledResponse>(
        &state,
        &path,
        Some(cookie),
        &SetAccountEnabledRequest {
            enabled: submission.enabled,
        },
    )
    .await
    {
        Ok(identity) => identity,
        Err(()) => {
            return account_redirect(&state, "", "unavailable", &headers);
        }
    };
    match identity.status {
        status
            if status.is_success()
                && identity
                    .body
                    .as_ref()
                    .is_some_and(|body| body.enabled == submission.enabled) =>
        {
            account_redirect(
                &state,
                if submission.enabled {
                    "account-enabled"
                } else {
                    "account-disabled"
                },
                "",
                &headers,
            )
        }
        StatusCode::UNAUTHORIZED => login_redirect(ACCOUNTS_PATH, &headers),
        StatusCode::FORBIDDEN => error_page(WebError::Forbidden),
        StatusCode::NOT_FOUND => account_redirect(&state, "", "not-found", &headers),
        StatusCode::BAD_REQUEST => account_redirect(&state, "", "invalid", &headers),
        StatusCode::SERVICE_UNAVAILABLE => {
            account_redirect(&state, "", "email-unavailable", &headers)
        }
        _ => account_redirect(&state, "", "unavailable", &headers),
    }
}

pub(super) async fn organizations(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = ORGANIZATIONS_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let organizations = match admin_connect::organizations(&state, cookie.clone()).await {
        Ok(organizations) => organizations,
        Err(error) => return admin_connect_error(error, &continuation, &headers),
    };
    let defaults = match admin_connect::default_quota(&state, cookie).await {
        Ok(defaults) => defaults,
        Err(error) => return admin_connect_error(error, &continuation, &headers),
    };
    let token = page_csrf_token(&headers);
    with_csrf_cookie(
        render_page(AdminOrganizationsTemplate {
            view: &dashboard,
            organizations: &organizations,
            defaults: &defaults,
            csrf_token: &token,
            message: defaults_message(&query.message),
            error: quota_error(&query.error),
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn set_default_quota(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<DefaultQuotaSubmission>,
) -> Response {
    let cookie = match admin_action_page_context_for(
        &state,
        &headers,
        &submission.csrf,
        &query.org,
        ORGANIZATIONS_PATH,
    )
    .await
    {
        Ok((_, cookie)) => cookie,
        Err(response) => return response,
    };
    let quota = QuotaMutation {
        environments: submission.environments,
        sandboxes: submission.sandboxes,
        cpu_millicores: submission.cpu_millicores,
        memory_mb: submission.memory_mb,
    };
    if !valid_quota(quota) {
        return admin_redirect_to(&state, ORGANIZATIONS_PATH, "", "invalid", &headers);
    }
    let result = admin_connect::set_default_quota(&state, cookie, quota).await;
    quota_response(
        &state,
        result,
        ORGANIZATIONS_PATH,
        "defaults-saved",
        &headers,
    )
}

pub(super) async fn organization(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_organization_id(&organization_id) {
        return error_page(WebError::NotFound);
    }
    let continuation = organization_path(&organization_id);
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let organization = match admin_connect::organization(&state, cookie, &organization_id).await {
        Ok(organization) => organization,
        Err(error) => return admin_connect_error(error, &continuation, &headers),
    };
    let token = page_csrf_token(&headers);
    with_csrf_cookie(
        render_page(AdminOrganizationTemplate {
            view: &dashboard,
            organization: &organization,
            csrf_token: &token,
            message: quota_message(&query.message),
            error: quota_error(&query.error),
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn set_organization_quota(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<QuotaSubmission>,
) -> Response {
    if !valid_organization_id(&submission.organization_id) {
        return error_page(WebError::NotFound);
    }
    let path = organization_path(&submission.organization_id);
    let cookie =
        match admin_action_page_context_for(&state, &headers, &submission.csrf, &query.org, &path)
            .await
        {
            Ok((_, cookie)) => cookie,
            Err(response) => return response,
        };
    let quota = QuotaMutation {
        environments: submission.environments,
        sandboxes: submission.sandboxes,
        cpu_millicores: submission.cpu_millicores,
        memory_mb: submission.memory_mb,
    };
    if !valid_quota(quota) {
        return admin_redirect_to(&state, &path, "", "invalid", &headers);
    }
    let result =
        admin_connect::set_organization_quota(&state, cookie, &submission.organization_id, quota)
            .await;
    quota_response(&state, result, &path, "quota-saved", &headers)
}

pub(super) async fn clear_organization_quota(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<QuotaClearSubmission>,
) -> Response {
    if !valid_organization_id(&submission.organization_id) {
        return error_page(WebError::NotFound);
    }
    let path = organization_path(&submission.organization_id);
    let cookie =
        match admin_action_page_context_for(&state, &headers, &submission.csrf, &query.org, &path)
            .await
        {
            Ok((_, cookie)) => cookie,
            Err(response) => return response,
        };
    let result =
        admin_connect::clear_organization_quota(&state, cookie, &submission.organization_id).await;
    quota_response(&state, result, &path, "quota-cleared", &headers)
}

/// Opt an organization in to, or out of, confidential environments (#2497),
/// from its admin page. Global administrators only; the billing service owns
/// the opt-in, checks the administrator again and writes the audit event.
pub(super) async fn set_organization_confidential(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<ConfidentialOrganizationSubmission>,
) -> Response {
    if !valid_organization_id(&submission.organization_id) {
        return error_page(WebError::NotFound);
    }
    let path = organization_path(&submission.organization_id);
    let cookie =
        match admin_action_page_context_for(&state, &headers, &submission.csrf, &query.org, &path)
            .await
        {
            Ok((_, cookie)) => cookie,
            Err(response) => return response,
        };
    let slug = submission.organization_slug;
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug) {
        return admin_redirect_to(&state, &path, "", "not-found", &headers);
    }
    let result =
        admin_connect::set_confidential_environments(&state, cookie, slug, submission.enabled)
            .await;
    match result {
        Ok(()) => admin_redirect_to(
            &state,
            &path,
            if submission.enabled {
                "confidential-enabled"
            } else {
                "confidential-disabled"
            },
            "",
            &headers,
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&path, &headers),
        Err(error) => {
            let code = match mutation_error(&error) {
                "unavailable" | "conflict" => "confidential-unavailable",
                code => code,
            };
            admin_redirect_to(&state, &path, "", code, &headers)
        }
    }
}

pub(super) async fn audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = AUDIT_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
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
        Err(error) => return admin_connect_error(error, &continuation, &headers),
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
    let continuation = BILLING_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let token = page_csrf_token(&headers);
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
        Err(error) => return admin_connect_error(error, &continuation, &headers),
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
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<PlanSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf, &query.org).await {
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
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<PlanSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf, &query.org).await {
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
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<ArchivePlanSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf, &query.org).await {
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
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<PriceSubmission>,
) -> Response {
    price_action(&state, &headers, submission, true, &query.org).await
}

pub(super) async fn update_price(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<PriceSubmission>,
) -> Response {
    price_action(&state, &headers, submission, false, &query.org).await
}

pub(super) async fn archive_price(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<ArchivePriceSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf, &query.org).await {
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
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<SettingSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf, &query.org).await {
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
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<MigrationSubmission>,
) -> Response {
    let (dashboard, cookie) =
        match admin_action_page_context(&state, &headers, &submission.csrf, &query.org).await {
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
        Err(error) => {
            return admin_connect_error(error, BILLING_PATH, &headers);
        }
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
        Err(error) => {
            return admin_connect_error(error, BILLING_PATH, &headers);
        }
    };
    catalog.message = "Migration preview updated.".to_owned();
    render_page(AdminBillingTemplate {
        view: &dashboard,
        catalog: &catalog,
    })
}

pub(super) async fn run_migration(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<MigrationSubmission>,
) -> Response {
    let cookie = match admin_action_context(&state, &headers, &submission.csrf, &query.org).await {
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
    selected_slug: &str,
) -> Response {
    let cookie = match admin_action_context(state, headers, &submission.csrf, selected_slug).await {
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

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn admin_context(
    state: &AppState,
    headers: &HeaderMap,
    continuation: &str,
    selected_slug: &str,
) -> Result<(DashboardView, HeaderValue), Response> {
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| admin_route_error(error, continuation, headers))?;
    enforce_two_factor(&identity)
        .map_err(|error| admin_route_error(error, continuation, headers))?;
    let cookie = canonical_cookie(headers).map_err(|()| login_redirect(continuation, headers))?;
    let mut dashboard =
        dashboard_shell_view_from_identity(state, headers, &identity, cookie.clone())
            .await
            .map_err(|error| admin_route_error(error, continuation, headers))?;
    select_shell_organization(state, cookie.clone(), &mut dashboard, selected_slug)
        .await
        .map_err(|error| admin_route_error(error, continuation, headers))?;
    if !identity.is_admin {
        return Err(redirect("/dashboard/".to_owned(), headers));
    }
    Ok((dashboard, cookie))
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn admin_action_context(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    selected_slug: &str,
) -> Result<HeaderValue, Response> {
    admin_action_page_context(state, headers, csrf, selected_slug)
        .await
        .map(|(_, cookie)| cookie)
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn admin_action_page_context(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    selected_slug: &str,
) -> Result<(DashboardView, HeaderValue), Response> {
    admin_action_page_context_for(state, headers, csrf, selected_slug, BILLING_PATH).await
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn admin_action_page_context_for(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    selected_slug: &str,
    path: &str,
) -> Result<(DashboardView, HeaderValue), Response> {
    if !request_has_same_origin(headers, &state.public_origin) || !valid_csrf_token(headers, csrf) {
        return Err(error_page(WebError::CsrfRejected));
    }
    let continuation = path.to_owned();
    admin_context(state, headers, &continuation, selected_slug).await
}

fn account_access_view(account: &AccountAccessResponse) -> AccountAccessView {
    let name = account
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("No name supplied")
        .to_owned();
    let reason = account
        .access_reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("No access request supplied")
        .to_owned();
    AccountAccessView {
        id: account.id.clone(),
        email: account.email.clone(),
        name,
        email_verified: account.email_verified,
        enabled: account.enabled,
        reason,
        has_reason: account.access_reason.is_some(),
        created_at: account.created_at.clone(),
    }
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
    admin_redirect_to(state, BILLING_PATH, message, error, headers)
}

fn account_redirect(state: &AppState, message: &str, error: &str, headers: &HeaderMap) -> Response {
    admin_redirect_to(state, ACCOUNTS_PATH, message, error, headers)
}

fn admin_redirect_to(
    state: &AppState,
    path: &str,
    message: &str,
    error: &str,
    headers: &HeaderMap,
) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if !message.is_empty() {
        query.append_pair("message", message);
    } else if !error.is_empty() {
        query.append_pair("error", error);
    }
    let query = query.finish();
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let token = new_csrf_token();
    with_csrf_cookie(
        redirect(target, headers),
        csrf_cookie(&state.public_origin, &token),
    )
}

/// Organization ids reach a URL path, so only the characters ids are made of
/// are accepted.
fn valid_organization_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn organization_path(organization_id: &str) -> String {
    format!("{ORGANIZATIONS_PATH}{organization_id}/")
}

/// Each limit is -1 (unlimited) or positive, as the server requires.
fn valid_quota(quota: QuotaMutation) -> bool {
    [
        quota.environments,
        quota.sandboxes,
        quota.cpu_millicores,
        quota.memory_mb,
    ]
    .into_iter()
    .all(|value| value == -1 || value > 0)
}

fn quota_response(
    state: &AppState,
    result: Result<(), ConnectError>,
    path: &str,
    message: &str,
    headers: &HeaderMap,
) -> Response {
    match result {
        Ok(()) => admin_redirect_to(state, path, message, "", headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(path, headers),
        Err(error) => admin_redirect_to(state, path, "", mutation_error(&error), headers),
    }
}

fn quota_message(value: &str) -> &'static str {
    match value {
        "quota-saved" => "Environment quota saved.",
        "quota-cleared" => "Environment quota cleared; the plan fallback applies.",
        "confidential-enabled" => "Organization opted in to confidential environments.",
        "confidential-disabled" => "Organization removed from confidential environments.",
        _ => "",
    }
}

fn defaults_message(value: &str) -> &'static str {
    match value {
        "defaults-saved" => "Default environment limits saved.",
        _ => "",
    }
}

fn quota_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to change environment quotas.",
        "invalid" => "Each limit must be a positive number, or -1 for unlimited.",
        "not-found" => "The organization no longer exists.",
        "conflict" | "unavailable" => "Environment quotas are temporarily unavailable.",
        "confidential-unavailable" => "Confidential environments are temporarily unavailable.",
        _ => "",
    }
}

fn account_message(value: &str) -> &'static str {
    match value {
        "account-enabled" => "Account enabled and access email sent.",
        "account-disabled" => "Account disabled.",
        _ => "",
    }
}

fn account_error(value: &str) -> &'static str {
    match value {
        "invalid" => "Verify the account email before enabling access.",
        "not-found" => "The account no longer exists.",
        "email-unavailable" => {
            "Access was updated, but the ready email was not sent. Select Enable again to retry."
        }
        "unavailable" => "Account access is temporarily unavailable.",
        _ => "",
    }
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
    fn organization_ids_and_quota_limits_are_an_exact_allowlist() {
        assert!(valid_organization_id("org_1-A"));
        for refused in [
            "",
            "../admin",
            "org/1",
            "org 1",
            "org?x=1",
            &"a".repeat(129),
        ] {
            assert!(!valid_organization_id(refused), "{refused:?}");
        }
        assert_eq!(organization_path("org_1"), "/admin/organizations/org_1/");
        let quota = QuotaMutation {
            environments: -1,
            sandboxes: 200,
            cpu_millicores: 400_000,
            memory_mb: 1_600_000,
        };
        assert!(valid_quota(quota));
        assert!(!valid_quota(QuotaMutation {
            sandboxes: 0,
            ..quota
        }));
        assert!(!valid_quota(QuotaMutation {
            memory_mb: -2,
            ..quota
        }));
        assert_eq!(quota_message("quota-saved"), "Environment quota saved.");
        assert_eq!(quota_message("<script>"), "");
        assert_eq!(
            defaults_message("defaults-saved"),
            "Default environment limits saved."
        );
        assert_eq!(defaults_message("quota-saved"), "");
        assert_eq!(quota_error("<script>"), "");
    }

    #[test]
    fn audit_filters_and_pagination_are_bounded_and_encoded() {
        let query = normalize_audit_query(AuditQuery {
            org: "selected-org".into(),
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
                org: String::new(),
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
