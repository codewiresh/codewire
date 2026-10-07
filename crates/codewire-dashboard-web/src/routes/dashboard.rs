use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;

use crate::{
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    connect::organizations,
    dependency::{DependencyResult, PageDependency, resolve_web},
    error::WebError,
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    routes::{DASHBOARD_PATH, NEW_ORGANIZATION_PATH},
    security::{canonical_cookie, cookie_value},
    state::AppState,
    templates::DashboardTemplate,
    view::{DashboardView, OrganizationRow, PageCsrfToken},
};

#[derive(Debug, Default, Deserialize)]
pub(super) struct DashboardQuery {
    #[serde(default)]
    org: String,
}

/// The account home. With an organization it is that organization's home,
/// `/{slug}/`, chosen from the remembered organization or else the first one;
/// without one it offers to create an organization.
pub(super) async fn dashboard(
    State(state): State<AppState>,
    Query(query): Query<DashboardQuery>,
    headers: HeaderMap,
) -> Response {
    match dashboard_view(&state, &headers).await {
        Ok(view) => {
            let home = view
                .organizations
                .iter()
                .find(|organization| organization.slug == query.org)
                .or_else(|| view.organizations.first());
            match home {
                Some(organization) => redirect(format!("/{}/", organization.slug), &headers),
                None => render_page(DashboardTemplate { view: &view }),
            }
        }
        Err(WebError::Unauthorized) => login_redirect(DASHBOARD_PATH, &headers),
        Err(WebError::TwoFactorRequired) => two_factor_redirect(DASHBOARD_PATH, &headers),
        Err(error) => error_page(error),
    }
}

pub(super) async fn dashboard_view(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<DashboardView, WebError> {
    let identity = authenticated_identity(state, headers).await?;
    enforce_two_factor(&identity)?;
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    let organizations = organizations(state, cookie).await;
    let organizations = match resolve_web(PageDependency::DashboardOrganizations, organizations)? {
        DependencyResult::Available(organizations) => organizations,
        DependencyResult::Unavailable => {
            unreachable!("required dashboard organizations cannot degrade")
        }
    };
    let has_organizations = !organizations.is_empty();

    Ok(DashboardView {
        user_name: identity.display_name().to_owned(),
        csrf_token: PageCsrfToken::from_headers(headers),
        is_admin: identity.is_admin,
        organizations,
        has_organizations,
        organization_navigation_unavailable: false,
        new_organization_url: NEW_ORGANIZATION_PATH.to_owned(),
        settings_url: "/settings/".to_owned(),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_rail_loading: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
        sidebar_collapsed: sidebar_collapsed(headers),
    })
}

/// Load only the authenticated shell fields used by nested product routes.
/// Organization pages load only the account identity and organization state
/// needed to render a sidebar or complete a mutation response.
pub(super) async fn dashboard_shell_view(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<DashboardView, WebError> {
    let identity = authenticated_identity(state, headers).await?;
    enforce_two_factor(&identity)?;
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    dashboard_shell_view_from_identity(state, headers, &identity, cookie).await
}

/// Build the shared dashboard shell after a route has completed its own
/// identity checks. Admin routes use this to ensure no privileged RPC is sent
/// until the local global-admin bit has been checked.
pub(super) async fn dashboard_shell_view_from_identity(
    state: &AppState,
    headers: &HeaderMap,
    identity: &IdentityUser,
    cookie: axum::http::HeaderValue,
) -> Result<DashboardView, WebError> {
    let organizations = organizations(state, cookie).await?;
    Ok(shell_from_organizations(
        headers,
        identity,
        organizations,
        false,
    ))
}

fn shell_from_organizations(
    headers: &HeaderMap,
    identity: &IdentityUser,
    organizations: Vec<OrganizationRow>,
    organization_navigation_unavailable: bool,
) -> DashboardView {
    let has_organizations = !organizations.is_empty();
    DashboardView {
        user_name: identity.display_name().to_owned(),
        csrf_token: PageCsrfToken::from_headers(headers),
        is_admin: identity.is_admin,
        organizations,
        has_organizations,
        organization_navigation_unavailable,
        new_organization_url: NEW_ORGANIZATION_PATH.to_owned(),
        settings_url: "/settings/".to_owned(),
        has_selected_organization: false,
        selected_organization_name: String::new(),
        selected_organization_slug: String::new(),
        selected_organization_url: String::new(),
        sandboxes: Vec::new(),
        recent_sandboxes: Vec::new(),
        sandbox_rail_available: false,
        sandbox_rail_loading: false,
        sandbox_total: 0,
        sandbox_running: 0,
        sandbox_stopped: 0,
        sandbox_attention: 0,
        provisioned_cpu_millicores: 0,
        provisioned_memory_mb: 0,
        provisioned_disk_gb: 0,
        sidebar_collapsed: sidebar_collapsed(headers),
    }
}

/// Whether this browser collapsed the desktop sidebar. The cookie holds only
/// that choice, so the page renders it at once rather than after its script.
pub(crate) fn sidebar_collapsed(headers: &HeaderMap) -> bool {
    cookie_value(headers, SIDEBAR_COOKIE_NAME) == Some("collapsed")
}

pub(crate) const SIDEBAR_COOKIE_NAME: &str = "codewire.sidebar";

/// Personal settings have their own authority. An organization is optional
/// navigation context, never a prerequisite for current-user resources.
pub(super) async fn personal_settings_shell_view(
    state: &AppState,
    headers: &HeaderMap,
    selected_slug: &str,
) -> Result<DashboardView, WebError> {
    if !crate::account_sessions::cookie_authority_is_unique(headers) {
        return Err(WebError::Unauthorized);
    }
    let identity = authenticated_identity(state, headers).await?;
    enforce_two_factor(&identity)?;
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    personal_settings_shell_view_from_identity(state, headers, &identity, cookie, selected_slug)
        .await
}

pub(super) async fn personal_settings_shell_view_from_identity(
    state: &AppState,
    headers: &HeaderMap,
    identity: &IdentityUser,
    cookie: axum::http::HeaderValue,
    selected_slug: &str,
) -> Result<DashboardView, WebError> {
    let dependency = resolve_web(
        PageDependency::PersonalSettingsOrganizations,
        organizations(state, cookie.clone()).await,
    )?;
    let (organizations, unavailable) = match dependency {
        DependencyResult::Available(rows) => (rows, false),
        DependencyResult::Unavailable => (Vec::new(), true),
    };
    personal_settings_shell_view_from_organizations(
        state,
        headers,
        identity,
        cookie,
        selected_slug,
        organizations,
        unavailable,
    )
    .await
}

/// Reuse the exact memberships already validated by a personal resource route.
/// In particular, one-time creation responses must not start a second optional
/// metadata read after successfully receiving the new secret material.
pub(super) async fn personal_settings_shell_view_from_organizations(
    state: &AppState,
    headers: &HeaderMap,
    identity: &IdentityUser,
    cookie: axum::http::HeaderValue,
    selected_slug: &str,
    organizations: Vec<OrganizationRow>,
    unavailable: bool,
) -> Result<DashboardView, WebError> {
    let mut view = shell_from_organizations(headers, identity, organizations, unavailable);
    // Missing or inaccessible context is discarded without resolving any
    // organization that was not returned for this exact authenticated caller.
    let Some(organization) = view
        .organizations
        .iter()
        .find(|row| !selected_slug.is_empty() && row.slug == selected_slug)
        .map(crate::view::OrganizationContext::from_row)
    else {
        return Ok(view);
    };
    let rail = resolve_web(
        PageDependency::PersonalSettingsSandboxRail,
        crate::environment_connect::environments(state, cookie, &organization.id, false)
            .await
            .map_err(WebError::Connect),
    )?;
    let (sandboxes, available) = match rail {
        DependencyResult::Available(rows) => (rows, true),
        DependencyResult::Unavailable => (Vec::new(), false),
    };
    view.select_organization(&organization, sandboxes, available);
    Ok(view)
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
    // The selection is only navigation: a slug the caller cannot see selects
    // nothing rather than failing the page.
    let Some(row) = view
        .organizations
        .iter()
        .find(|organization| organization.slug == selected_slug)
    else {
        return Ok(());
    };
    let organization = crate::view::OrganizationContext::from_row(row);
    let rail =
        crate::environment_connect::environments(state, cookie, &organization.id, false).await;
    let rail_available = rail.is_ok();
    view.select_organization(&organization, rail.unwrap_or_default(), rail_available);
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::sidebar_collapsed;

    #[test]
    fn only_the_sidebar_cookie_collapses_the_sidebar() {
        let mut headers = HeaderMap::new();
        assert!(!sidebar_collapsed(&headers));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire.session_token=token; codewire.sidebar=collapsed"),
        );
        assert!(sidebar_collapsed(&headers));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("codewire.sidebar=open"),
        );
        assert!(!sidebar_collapsed(&headers));
    }
}
