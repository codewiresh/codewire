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
        canonical_cookie, clear_scoped_cookie, csrf_cookie, new_csrf_token,
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
    let continuation = global_settings_path(SETTINGS_PATH, &query.org);
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
        return settings_redirect("invalid-session-page", true, &query.org, &headers);
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
    let csrf = new_csrf_token();
    let mut settings = SettingsPageView {
        account_id: identity.id.clone(),
        account_name: identity.display_name().into(),
        account_email: identity.email().into(),
        email_verified: identity.email_verified(),
        account_created: display_time(Some(identity.created_at())),
        two_factor_enabled: identity.two_factor_enabled(),
        first_sessions_url: format!(
            "{}#sessions",
            global_settings_path(SETTINGS_PATH, &query.org)
        ),
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
        if let Some(next) = inventory.next_cursor {
            let mut query_string = url::form_urlencoded::Serializer::new(String::new());
            if !query.org.is_empty() {
                query_string.append_pair("org", &query.org);
            }
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
    Query(query): Query<SettingsQuery>,
    headers: HeaderMap,
    form: Result<Form<RevokeSessionForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    if !account_sessions::cookie_authority_is_unique(&headers) {
        return private(login_redirect(
            &global_settings_path(SETTINGS_PATH, &query.org),
            &headers,
        ));
    }
    if !account_sessions::mutation_origin_is_exact(&headers, &state.public_origin) {
        return private(error_page(WebError::CsrfRejected));
    }
    let identity = match authenticated_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => {
            return private(login_redirect(
                &global_settings_path(SETTINGS_PATH, &query.org),
                &headers,
            ));
        }
        Err(error) => return private(error_page(error)),
    };
    if identity.id != form.account_id || !account_sessions::valid_id(&form.account_id) {
        return private(settings_redirect(
            "account-changed",
            true,
            &query.org,
            &headers,
        ));
    }
    let cookie =
        match mutation_cookie(&state, &headers, &form.csrf, &query.org, SETTINGS_PATH).await {
            Ok(cookie) => cookie,
            Err(response) => return private(response),
        };
    let acknowledgement =
        account_sessions::revoke(&state, cookie, &form.account_id, &form.session_id).await;
    revocation_response(&state.public_origin, &headers, &query.org, acknowledgement)
}

fn revocation_response(
    public_origin: &str,
    headers: &HeaderMap,
    org: &str,
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
        Ok(_) => settings_redirect("session-revoked", false, org, headers),
        Err(account_sessions::Failure::Unauthorized) => {
            login_redirect(&global_settings_path(SETTINGS_PATH, org), headers)
        }
        Err(account_sessions::Failure::Forbidden) => {
            settings_redirect("session-controls-unavailable", true, org, headers)
        }
        Err(account_sessions::Failure::NoLongerAvailable) => {
            settings_redirect("session-no-longer-available", true, org, headers)
        }
        Err(_) => settings_redirect("session-outcome-unknown", true, org, headers),
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
    let continuation = global_settings_path(path, selected_slug);
    if !account_sessions::cookie_authority_is_unique(headers) {
        return private(login_redirect(&continuation, headers));
    }
    let dashboard =
        match super::dashboard::personal_settings_shell_view(state, headers, selected_slug).await {
            Ok(dashboard) => dashboard,
            Err(WebError::Unauthorized) => return login_redirect(&continuation, headers),
            Err(WebError::TwoFactorRequired) => return two_factor_redirect(&continuation, headers),
            Err(error) => return error_page(error),
        };
    private(redirect(
        format!(
            "{}#{section}",
            global_settings_path(SETTINGS_PATH, &dashboard.selected_organization_slug)
        ),
        headers,
    ))
}

pub(super) async fn mutation_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    selected_slug: &str,
    path: &str,
) -> Result<axum::http::HeaderValue, Response> {
    let continuation = global_settings_path(path, selected_slug);
    if !account_sessions::cookie_authority_is_unique(headers) {
        return Err(login_redirect(&continuation, headers));
    }
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => login_redirect(&continuation, headers),
            error => error_page(error),
        })?;
    if enforce_two_factor(&identity).is_err() {
        return Err(two_factor_redirect(&continuation, headers));
    }
    if !request_has_same_origin(headers, &state.public_origin) || !valid_csrf_token(headers, csrf) {
        return Err(error_page(WebError::CsrfRejected));
    }
    // These actions mutate current-user resources. Optional navigation context
    // cannot grant authority and must not make a personal write depend on an
    // organization list or sandbox inventory being available.
    canonical_cookie(headers).map_err(|()| login_redirect(&continuation, headers))
}

fn global_settings_path(path: &str, selected_slug: &str) -> String {
    if selected_slug.is_empty() {
        path.to_owned()
    } else {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("org", selected_slug);
        format!("{path}?{}", query.finish())
    }
}

fn settings_redirect(
    code: &str,
    error: bool,
    selected_slug: &str,
    headers: &HeaderMap,
) -> Response {
    let key = if error { "error" } else { "message" };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if !selected_slug.is_empty() {
        query.append_pair("org", selected_slug);
    }
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
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
            organization_navigation_unavailable: false,
            show_checklist: false,
            new_organization_url: "/organizations/new/".into(),
            settings_url: SETTINGS_PATH.into(),
            global_context_query: String::new(),
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
    fn global_settings_context_is_query_encoded() {
        assert_eq!(
            global_settings_path(SETTINGS_PATH, "selected org&mode=other"),
            "/settings/?org=selected+org%26mode%3Dother"
        );
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
        assert_eq!(
            body.matches("name=\"account_id\" value=\"account-1\"")
                .count(),
            2
        );
        for id in ["session-current", "session-other"] {
            assert!(body.contains(&format!("name=\"session_id\" value=\"{id}\"")));
            assert!(body.contains(&format!("data-dialog-open=\"revoke-session-{id}\"")));
            assert!(body.contains(&format!("data-dialog id=\"revoke-session-{id}\"")));
        }
        assert_eq!(
            body.matches("data-dialog-close autofocus>Cancel").count(),
            2
        );
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
                "sample-org",
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
                    "/settings/?org=sample-org&message=session-revoked#sessions"
                );
            }
        }
        for failure in [
            account_sessions::Failure::UnknownOutcome,
            account_sessions::Failure::NoLongerAvailable,
            account_sessions::Failure::Forbidden,
        ] {
            let response = revocation_response(
                "https://app.example.test",
                &headers,
                "sample-org",
                Err(failure),
            );
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
