use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use serde::Deserialize;

use crate::{
    account_sessions,
    auth::{authenticated_identity, enforce_two_factor},
    error::WebError,
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    security::{
        canonical_cookie, clear_scoped_cookie, csrf_cookie, page_csrf_token,
        request_has_same_origin, valid_csrf_token, with_csrf_cookie, with_response_cookie,
    },
    state::AppState,
    templates::SettingsTemplate,
    view::{AccountSessionRowView, SettingsPageView},
};

const SETTINGS_PATH: &str = "/settings/";

#[derive(Debug, Default, Deserialize)]
pub(super) struct SettingsQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    cursor: Option<String>,
}

pub(super) async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(mut query): Query<SettingsQuery>,
) -> Response {
    let continuation = SETTINGS_PATH.to_owned();
    if !account_sessions::cookie_authority_is_unique(&headers) {
        return login_redirect(&continuation, &headers);
    }
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(error) => return error_page(error),
    };
    if enforce_two_factor(&identity).is_err() {
        return two_factor_redirect(&continuation, &headers);
    }
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return login_redirect(&continuation, &headers),
    };
    let dashboard = match super::dashboard::personal_settings_shell_view_from_identity(
        &state,
        &headers,
        &identity,
        cookie.clone(),
        &query.org,
    )
    .await
    {
        Ok(view) => view,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(WebError::TwoFactorRequired) => {
            return two_factor_redirect(&continuation, &headers);
        }
        Err(error) => return error_page(error),
    };
    query.org = dashboard.selected_organization_slug.clone();
    if query
        .cursor
        .as_deref()
        .is_some_and(|cursor| !account_sessions::valid_id(cursor))
    {
        return settings_redirect("invalid-session-page", true, &headers);
    }
    let inventory =
        match account_sessions::inventory(&state, cookie, &identity.id, query.cursor.as_deref())
            .await
        {
            Ok(inventory) => Some(inventory),
            Err(account_sessions::Failure::Unauthorized) => {
                return login_redirect(&continuation, &headers);
            }
            Err(_) => None,
        };
    let csrf = page_csrf_token(&headers);
    let mut settings = SettingsPageView {
        account_id: identity.id.clone(),
        account_name: identity.display_name().into(),
        account_email: identity.email().into(),
        email_verified: identity.email_verified(),
        account_created: display_time(Some(identity.created_at())),
        two_factor_enabled: identity.two_factor_enabled(),
        first_sessions_url: format!("{}#sessions", SETTINGS_PATH.to_owned()),
        csrf_token: csrf.clone(),
        message: approved_message(&query.message).to_owned(),
        error: approved_error(&query.error).to_owned(),
        ..Default::default()
    };
    if let Some(inventory) = inventory {
        settings.sessions_available = true;
        settings.current_session_id = inventory.current_session.id.clone();
        settings.current_session_expiry = display_time(Some(&inventory.current_session.expires_at));
        settings.sessions = inventory
            .sessions
            .into_iter()
            .map(|session| AccountSessionRowView {
                current: session.id == inventory.current_session.id,
                id: session.id,
                created: display_time(session.created_at.as_deref()),
                expires: display_time(Some(&session.expires_at)),
            })
            .collect();
        // This browser leads its page; the rest keep the IdP's order.
        settings.sessions.sort_by_key(|session| !session.current);
        settings.current_session_listed = settings.sessions.iter().any(|session| session.current);
        settings.later_sessions_page = query
            .cursor
            .as_deref()
            .is_some_and(|cursor| !cursor.is_empty());
        if let Some(next) = inventory.next_cursor {
            let mut query_string = url::form_urlencoded::Serializer::new(String::new());
            query_string.append_pair("cursor", &next);
            settings.next_sessions_url =
                format!("{SETTINGS_PATH}?{}#sessions", query_string.finish());
        }
    }
    private(with_csrf_cookie(
        render_page(SettingsTemplate {
            view: &dashboard,
            settings: &settings,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    ))
}

// No Debug: the CSRF field is request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevokeSessionForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    session_id: String,
}

pub(super) async fn revoke_session_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<RevokeSessionForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    if !account_sessions::cookie_authority_is_unique(&headers) {
        return private(login_redirect(SETTINGS_PATH, &headers));
    }
    if !account_sessions::mutation_origin_is_exact(&headers, &state.public_origin) {
        return private(error_page(WebError::CsrfRejected));
    }
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => {
            return private(login_redirect(SETTINGS_PATH, &headers));
        }
        Err(error) => return private(error_page(error)),
    };
    if identity.id != form.account_id || !account_sessions::valid_id(&form.account_id) {
        return private(settings_redirect("account-changed", true, &headers));
    }
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, SETTINGS_PATH).await {
        Ok(cookie) => cookie,
        Err(response) => return private(response),
    };
    let acknowledgement =
        account_sessions::revoke(&state, cookie, &form.account_id, &form.session_id).await;
    revocation_response(&state.public_origin, &headers, acknowledgement)
}

fn revocation_response(
    public_origin: &str,
    headers: &HeaderMap,
    acknowledgement: Result<account_sessions::Revoked, account_sessions::Failure>,
) -> Response {
    private(match acknowledgement {
        Ok(ack) if ack.current_session_revoked => with_response_cookie(
            redirect("/login".into(), headers),
            clear_scoped_cookie(
                public_origin,
                codewire_server_core::auth::SESSION_COOKIE_NAME,
                "/",
            ),
        ),
        Ok(_) => settings_redirect("session-revoked", false, headers),
        Err(account_sessions::Failure::Unauthorized) => login_redirect(SETTINGS_PATH, headers),
        Err(account_sessions::Failure::Forbidden) => {
            settings_redirect("session-controls-unavailable", true, headers)
        }
        Err(account_sessions::Failure::NoLongerAvailable) => {
            settings_redirect("session-no-longer-available", true, headers)
        }
        Err(_) => settings_redirect("session-outcome-unknown", true, headers),
    })
}

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response
}

fn display_time(value: Option<&str>) -> String {
    value
        .filter(|time| account_sessions::valid_time(time))
        .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
        .map(|time| crate::time_display::calendar_datetime(time.timestamp()))
        .unwrap_or_else(|| "Unavailable".into())
}

pub(super) async fn security(
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
    headers: HeaderMap,
) -> Response {
    section_redirect(
        &state,
        &headers,
        "/settings/security/",
        &query.org,
        "security",
    )
    .await
}

pub(super) async fn sessions(
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
    headers: HeaderMap,
) -> Response {
    section_redirect(
        &state,
        &headers,
        "/settings/sessions/",
        &query.org,
        "sessions",
    )
    .await
}

async fn section_redirect(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    selected_slug: &str,
    section: &'static str,
) -> Response {
    let continuation = path.to_owned();
    if !account_sessions::cookie_authority_is_unique(headers) {
        return private(login_redirect(&continuation, headers));
    }
    match super::dashboard::personal_settings_shell_view(state, headers, selected_slug).await {
        Ok(_) => {}
        Err(WebError::Unauthorized) => return login_redirect(&continuation, headers),
        Err(WebError::TwoFactorRequired) => return two_factor_redirect(&continuation, headers),
        Err(error) => return error_page(error),
    }
    private(redirect(format!("{SETTINGS_PATH}#{section}"), headers))
}

pub(super) async fn mutation_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    path: &str,
) -> Result<axum::http::HeaderValue, Response> {
    mutation_cookie_with_continuation(state, headers, csrf, path).await
}

// The caller supplies a closed, route-owned continuation. It changes only
// login/2FA navigation, never organization selection or mutation authority.
pub(super) async fn mutation_cookie_with_continuation(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    continuation: &str,
) -> Result<axum::http::HeaderValue, Response> {
    if !account_sessions::cookie_authority_is_unique(headers) {
        return Err(login_redirect(continuation, headers));
    }
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => login_redirect(continuation, headers),
            error => error_page(error),
        })?;
    if enforce_two_factor(&identity).is_err() {
        return Err(two_factor_redirect(continuation, headers));
    }
    if !request_has_same_origin(headers, &state.public_origin) || !valid_csrf_token(headers, csrf) {
        return Err(error_page(WebError::CsrfRejected));
    }
    // These actions mutate current-user resources. Optional navigation context
    // cannot grant authority and must not make a personal write depend on an
    // organization list or sandbox inventory being available.
    canonical_cookie(headers).map_err(|()| login_redirect(continuation, headers))
}

fn settings_redirect(code: &str, error: bool, headers: &HeaderMap) -> Response {
    let key = if error { "error" } else { "message" };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(key, code);
    redirect(
        format!("{SETTINGS_PATH}?{}#sessions", query.finish()),
        headers,
    )
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "session-revoked" => {
            "Session signed out. Sandbox terminals and provider credentials are unchanged."
        }
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "invalid-session-page" => "That session page is invalid. Review the first page below.",
        "account-changed" => {
            "Your account changed. Review the refreshed sessions before trying again."
        }
        "session-controls-unavailable" => {
            "Session controls are unavailable. Reload before trying again."
        }
        "session-no-longer-available" => {
            "That session is no longer available. Review the refreshed list below."
        }
        "session-outcome-unknown" => {
            "The sign-out outcome could not be confirmed. Review the refreshed list before trying again."
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use askama::Template as _;

    use super::*;
    use crate::{templates::SettingsTemplate, view::DashboardView};

    fn dashboard_view() -> DashboardView {
        DashboardView {
            user_name: "Dashboard User".into(),
            csrf_token: Default::default(),
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
            organization_navigation_unavailable: false,
            new_organization_url: "/organizations/new/".into(),
            settings_url: SETTINGS_PATH.into(),
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
        }
    }

    #[test]
    fn optional_outages_keep_unaffected_controls_and_hide_unknown_mutations() {
        let settings = SettingsPageView {
            csrf_token: "csrf".into(),
            account_name: "Dashboard User".into(),
            ..Default::default()
        };
        let body = SettingsTemplate {
            view: &dashboard_view(),
            settings: &settings,
        }
        .render()
        .expect("render degraded settings");

        assert!(body.contains("Session controls are unavailable"));
        assert!(body.contains("Dashboard User"));
        assert!(body.contains("/settings/_actions/sign-out"));
        assert!(!body.contains("/settings/_actions/sessions/revoke"));
        assert!(body.contains("/settings/"));
        assert!(!body.contains("upstream-sensitive-detail"));
        assert!(!body.contains("/settings/_actions/git-identity"));
    }

    #[test]
    fn retired_account_credential_products_are_absent_from_settings() {
        let settings = SettingsPageView {
            csrf_token: "csrf".into(),
            ..Default::default()
        };
        let body = SettingsTemplate {
            view: &dashboard_view(),
            settings: &settings,
        }
        .render()
        .expect("render account settings");

        for retired in [
            "Git authentication",
            "Create SSH key",
            "Regenerate key",
            "/settings/_actions/credentials/",
            "/settings/_actions/ssh/",
            "Connect GitHub",
            "/settings/_actions/github/",
            "/api/v1/github/",
        ] {
            assert!(
                !body.contains(retired),
                "retired surface remains: {retired}"
            );
        }
        assert!(!body.contains("Git identity"));
        assert!(!body.contains("/settings/_actions/git-identity"));
        for section in ["Account details", "Security", "Active sessions"] {
            assert!(body.contains(section));
        }
        assert!(!body.contains("href=\"/settings/security/"));
        assert!(!body.contains("href=\"/settings/sessions/"));
    }

    #[test]
    fn account_inventory_renders_all_rows_and_exact_native_confirmations() {
        let settings = SettingsPageView {
            account_id: "account-1".into(),
            csrf_token: "synthetic-csrf".into(),
            sessions_available: true,
            current_session_id: "session-current".into(),
            current_session_expiry: "September 17, 2026".into(),
            sessions: vec![
                AccountSessionRowView {
                    id: "session-current".into(),
                    current: true,
                    ..Default::default()
                },
                AccountSessionRowView {
                    id: "session-other".into(),
                    ..Default::default()
                },
            ],
            current_session_listed: true,
            first_sessions_url: "/settings/?org=sample#sessions".into(),
            next_sessions_url: "/settings/?org=sample&cursor=session-other#sessions".into(),
            ..Default::default()
        };
        let body = SettingsTemplate {
            view: &dashboard_view(),
            settings: &settings,
        }
        .render()
        .unwrap();
        // Other sessions are revoked through an exact native confirmation.
        assert_eq!(
            body.matches("name=\"account_id\" value=\"account-1\"")
                .count(),
            1
        );
        assert!(body.contains("name=\"session_id\" value=\"session-other\""));
        assert!(body.contains("data-dialog-open=\"revoke-session-session-other\""));
        assert!(body.contains("data-dialog id=\"revoke-session-session-other\""));
        assert_eq!(
            body.matches("data-dialog-close autofocus>Cancel").count(),
            1
        );
        // This browser's row signs it out directly, and it is the only sign-out form.
        assert!(!body.contains("revoke-session-session-current"));
        assert_eq!(body.matches("id=\"sign-out\"").count(), 1);
        assert_eq!(
            body.matches(">Sign out of this browser</button>").count(),
            1
        );
        assert!(!body.contains("First page"));
        assert!(body.contains("Next page"));
        assert!(body.contains("cursor=session-other"));
        assert!(!body.contains("<dialog open"));
        assert!(!body.contains("Session controls are unavailable"));
    }

    #[test]
    fn personal_navigation_is_consistent_on_account_credentials_and_organization_pages() {
        for nav in [
            include_str!("../../templates/settings-nav.html"),
            include_str!("../../templates/organization-settings-nav.html"),
        ] {
            assert!(nav.contains("settings-navigation.html"));
            assert!(!nav.contains("/settings/security/"));
            assert!(!nav.contains("/settings/sessions/"));
        }
        let navigation = include_str!("../../templates/settings-navigation.html");
        assert!(navigation.contains("/settings/credentials/"));
        assert!(navigation.contains("/settings/secrets/"));
        assert!(!navigation.contains("/settings/security/"));
        assert!(!navigation.contains("/settings/sessions/"));
    }

    #[test]
    fn only_a_current_session_acknowledgement_clears_the_browser_cookie() {
        let headers = HeaderMap::new();
        for current in [false, true] {
            let response = revocation_response(
                "https://app.example.test",
                &headers,
                Ok(account_sessions::Revoked {
                    revoked: true,
                    current_session_revoked: current,
                }),
            );
            assert_eq!(response.headers().contains_key(header::SET_COOKIE), current);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::VARY], "Cookie");
            if current {
                assert_eq!(response.headers()[header::LOCATION], "/login");
                let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
                assert!(cookie.contains("codewire.session_token="));
                assert!(cookie.contains("Max-Age=0"));
            } else {
                assert_eq!(
                    response.headers()[header::LOCATION],
                    "/settings/?message=session-revoked#sessions"
                );
            }
        }
        for failure in [
            account_sessions::Failure::UnknownOutcome,
            account_sessions::Failure::NoLongerAvailable,
            account_sessions::Failure::Forbidden,
        ] {
            let response = revocation_response("https://app.example.test", &headers, Err(failure));
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(
                !response.headers()[header::LOCATION]
                    .to_str()
                    .unwrap()
                    .contains("message=session-revoked")
            );
        }
    }
}
