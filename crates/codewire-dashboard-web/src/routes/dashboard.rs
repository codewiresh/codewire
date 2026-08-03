use axum::{extract::State, http::HeaderMap, response::Response};
use connectrpc::ErrorCode;
use url::Url;

use crate::{
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    connect::{github_status, organizations},
    error::WebError,
    response::{error_page, login_redirect, render_page, two_factor_redirect},
    routes::{DASHBOARD_PATH, NEW_ORGANIZATION_PATH},
    security::canonical_cookie,
    state::AppState,
    templates::DashboardTemplate,
    view::DashboardView,
};

pub(super) async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match dashboard_view(&state, &headers).await {
        Ok(view) => render_page(DashboardTemplate {
            organizations: &view.organizations,
            has_organizations: view.has_organizations,
            view: &view,
        }),
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
    let (organizations, github_status) = tokio::join!(
        organizations(state, cookie.clone()),
        github_status(state, cookie),
    );
    let organizations = organizations?;
    let (github_connected, github_available) = match github_status {
        Ok(connected) => (connected, true),
        Err(WebError::Connect(error)) if error.code == ErrorCode::Unauthenticated => {
            return Err(WebError::Unauthorized);
        }
        Err(_) => (false, false),
    };
    let has_organizations = !organizations.is_empty();
    let show_checklist = !has_organizations || !github_connected;

    Ok(DashboardView {
        user_name: identity.display_name().to_owned(),
        is_admin: identity.is_admin,
        organizations,
        has_organizations,
        github_connected,
        github_available,
        show_checklist,
        new_organization_url: NEW_ORGANIZATION_PATH.to_owned(),
        settings_url: "/dashboard/settings".to_owned(),
        admin_url: "/admin".to_owned(),
        github_connect_url: github_connect_url(state),
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
        settings_url: "/dashboard/settings".to_owned(),
        admin_url: "/admin".to_owned(),
        github_connect_url: github_connect_url(state),
    })
}

fn github_connect_url(state: &AppState) -> String {
    let mut url = Url::parse(&format!(
        "{}/api/v1/github/oauth/authorize",
        state.browser_api_origin
    ))
    .expect("validated API origin");
    url.query_pairs_mut()
        .append_pair("return_url", &format!("{}/dashboard", state.public_origin));
    url.into()
}
