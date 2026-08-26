use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use url::Url;

use crate::{
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    connect::{github_status, organizations},
    dependency::{DependencyResult, PageDependency, resolve_web},
    error::WebError,
    response::{error_page, login_redirect, render_page, two_factor_redirect},
    routes::{DASHBOARD_PATH, NEW_ORGANIZATION_PATH},
    security::canonical_cookie,
    state::AppState,
    templates::DashboardTemplate,
    view::DashboardView,
};

#[derive(Debug, Default, Deserialize)]
pub(super) struct DashboardQuery {
    #[serde(default)]
    org: String,
}

pub(super) async fn dashboard(
    State(state): State<AppState>,
    Query(query): Query<DashboardQuery>,
    headers: HeaderMap,
) -> Response {
    match dashboard_overview_view(&state, &headers, &query.org).await {
        Ok(view) => render_page(DashboardTemplate { view: &view }),
        Err(WebError::Unauthorized) => login_redirect(DASHBOARD_PATH, &headers),
        Err(WebError::TwoFactorRequired) => two_factor_redirect(DASHBOARD_PATH, &headers),
        Err(error) => error_page(error),
    }
}

async fn dashboard_overview_view(
    state: &AppState,
    headers: &HeaderMap,
    selected_slug: &str,
) -> Result<DashboardView, WebError> {
    let mut view = dashboard_view(state, headers).await?;
    let selected = if selected_slug.is_empty() {
        view.organizations.first()
    } else {
        view.organizations
            .iter()
            .find(|organization| organization.slug == selected_slug)
    };
    let Some(selected) = selected else {
        if selected_slug.is_empty() {
            view.show_checklist = true;
            return Ok(view);
        }
        return Err(WebError::NotFound);
    };
    let organization = crate::view::OrganizationContext::from_row(selected);
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    let sandboxes =
        crate::environment_connect::environments(state, cookie, &organization.id, false)
            .await
            .map_err(WebError::Connect)?;
    view.show_checklist = sandboxes.is_empty();
    view.select_organization(&organization, sandboxes, true);
    Ok(view)
}

pub(super) async fn dashboard_view(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<DashboardView, WebError> {
    let identity = authenticated_identity(state, headers).await?;
    enforce_two_factor(&identity)?;
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    let (organizations, github_status) = tokio::join!(
        organizations(state, cookie.clone()),
        github_status(state, cookie),
    );
    let organizations = match resolve_web(PageDependency::DashboardOrganizations, organizations)? {
        DependencyResult::Available(organizations) => organizations,
        DependencyResult::Unavailable => {
            unreachable!("required dashboard organizations cannot degrade")
        }
    };
    let (github_connected, github_available) =
        match resolve_web(PageDependency::DashboardGithubStatus, github_status)? {
            DependencyResult::Available(connected) => (connected, true),
            DependencyResult::Unavailable => (false, false),
        };
    let has_organizations = !organizations.is_empty();
    let show_checklist = !has_organizations;

    Ok(DashboardView {
        user_name: identity.display_name().to_owned(),
        is_admin: identity.is_admin,
        organizations,
        has_organizations,
        github_connected,
        github_available,
        show_checklist,
        new_organization_url: NEW_ORGANIZATION_PATH.to_owned(),
        settings_url: "/settings/".to_owned(),
        global_context_query: String::new(),
        github_connect_url: github_connect_url(state),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
    })
}

/// Load only the authenticated shell fields used by nested product routes.
/// Organization pages must not wait on unrelated GitHub integration state to
/// render a sidebar or complete a mutation response.
pub(super) async fn dashboard_shell_view(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<DashboardView, WebError> {
    let identity = authenticated_identity(state, headers).await?;
    enforce_two_factor(&identity)?;
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    dashboard_shell_view_from_identity(state, &identity, cookie).await
}

/// Build the shared dashboard shell after a route has completed its own
/// identity checks. Admin routes use this to ensure no privileged RPC is sent
/// until the local global-admin bit has been checked.
pub(super) async fn dashboard_shell_view_from_identity(
    state: &AppState,
    identity: &IdentityUser,
    cookie: axum::http::HeaderValue,
) -> Result<DashboardView, WebError> {
    let organizations = organizations(state, cookie).await?;
    let has_organizations = !organizations.is_empty();
    Ok(DashboardView {
        user_name: identity.display_name().to_owned(),
        is_admin: identity.is_admin,
        organizations,
        has_organizations,
        github_connected: false,
        github_available: false,
        show_checklist: false,
        new_organization_url: NEW_ORGANIZATION_PATH.to_owned(),
        settings_url: "/settings/".to_owned(),
        global_context_query: String::new(),
        github_connect_url: github_connect_url(state),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
    })
}

/// Apply an optional organization selection to a global authenticated page.
///
/// The selection is resolved exclusively from the caller's accessible
/// organizations. Unknown and inaccessible slugs intentionally share the same
/// not-found response.
pub(super) async fn select_shell_organization(
    state: &AppState,
    cookie: axum::http::HeaderValue,
    view: &mut DashboardView,
    selected_slug: &str,
) -> Result<(), WebError> {
    if selected_slug.is_empty() {
        return Ok(());
    }
    let row = view
        .organizations
        .iter()
        .find(|organization| organization.slug == selected_slug)
        .ok_or(WebError::NotFound)?;
    let organization = crate::view::OrganizationContext::from_row(row);
    let rail =
        crate::environment_connect::environments(state, cookie, &organization.id, false).await;
    let rail_available = rail.is_ok();
    view.select_organization(&organization, rail.unwrap_or_default(), rail_available);
    Ok(())
}

fn github_connect_url(state: &AppState) -> String {
    let mut url = Url::parse(&format!(
        "{}/api/v1/github/oauth/authorize",
        state.browser_api_origin
    ))
    .expect("validated API origin");
    url.query_pairs_mut()
        .append_pair("return_url", &format!("{}/dashboard/", state.public_origin));
    url.into()
}
