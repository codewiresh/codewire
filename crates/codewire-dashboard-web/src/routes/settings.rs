use axum::{
    Form,
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use connectrpc::ErrorCode;
use serde::Deserialize;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    connect::{settings_data, update_git_identity},
    error::WebError,
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::{SettingsPlaceholderTemplate, SettingsTemplate},
    view::{GitIdentitySubmission, SettingsPageView, SettingsPlaceholderView},
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
}

pub(super) async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
) -> Response {
    let continuation = global_settings_path(SETTINGS_PATH, &query.org);
    let mut dashboard = match super::dashboard::dashboard_shell_view(&state, &headers).await {
        Ok(view) => view,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(WebError::TwoFactorRequired) => {
            return two_factor_redirect(&continuation, &headers);
        }
        Err(error) => return error_page(error),
    };
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return login_redirect(&continuation, &headers),
    };
    if let Err(error) = super::dashboard::select_shell_organization(
        &state,
        cookie.clone(),
        &mut dashboard,
        &query.org,
    )
    .await
    {
        return error_page(error);
    }
    let data = match settings_data(&state, cookie).await {
        Ok(data) => data,
        Err(WebError::Connect(error)) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&continuation, &headers);
        }
        Err(error) => return error_page(error),
    };
    let csrf = new_csrf_token();
    let settings = SettingsPageView {
        data,
        csrf_token: csrf.clone(),
        message: approved_message(&query.message).to_owned(),
        error: approved_error(&query.error).to_owned(),
    };
    with_csrf_cookie(
        render_page(SettingsTemplate {
            view: &dashboard,
            settings: &settings,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

pub(super) async fn update_identity_action(
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
    headers: HeaderMap,
    Form(form): Form<GitIdentitySubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if form.git_name.len() > 256 || form.git_email.len() > 320 {
        return settings_redirect("identity-invalid", true, &query.org, &headers);
    }
    match update_git_identity(
        &state,
        cookie,
        form.git_name.trim().to_owned(),
        form.git_email.trim().to_owned(),
    )
    .await
    {
        Ok(()) => settings_redirect("identity-saved", false, &query.org, &headers),
        Err(error) => connect_mutation_error(error.code, &query.org, &headers),
    }
}

pub(super) async fn security(
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
    headers: HeaderMap,
) -> Response {
    placeholder(
        &state,
        &headers,
        "/settings/security/",
        &query.org,
        SettingsPlaceholderView {
            section: "security",
            title: "Security settings",
            heading: "Security settings",
            description: "Two-factor authentication and password controls.",
        },
    )
    .await
}

pub(super) async fn sessions(
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
    headers: HeaderMap,
) -> Response {
    placeholder(
        &state,
        &headers,
        "/settings/sessions/",
        &query.org,
        SettingsPlaceholderView {
            section: "sessions",
            title: "Active sessions",
            heading: "Active sessions",
            description: "Review sessions attached to your account.",
        },
    )
    .await
}

async fn placeholder(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    selected_slug: &str,
    view: SettingsPlaceholderView,
) -> Response {
    let continuation = global_settings_path(path, selected_slug);
    let mut dashboard = match super::dashboard::dashboard_shell_view(state, headers).await {
        Ok(dashboard) => dashboard,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, headers),
        Err(WebError::TwoFactorRequired) => return two_factor_redirect(&continuation, headers),
        Err(error) => return error_page(error),
    };
    let cookie = match canonical_cookie(headers) {
        Ok(cookie) => cookie,
        Err(()) => return login_redirect(&continuation, headers),
    };
    if let Err(error) =
        super::dashboard::select_shell_organization(state, cookie, &mut dashboard, selected_slug)
            .await
    {
        return error_page(error);
    }
    render_page(SettingsPlaceholderTemplate {
        view: &dashboard,
        page: &view,
    })
}

async fn mutation_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    selected_slug: &str,
) -> Result<axum::http::HeaderValue, Response> {
    let continuation = global_settings_path(SETTINGS_PATH, selected_slug);
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
    let cookie = canonical_cookie(headers).map_err(|()| login_redirect(&continuation, headers))?;
    if !selected_slug.is_empty() {
        let mut dashboard =
            super::dashboard::dashboard_shell_view_from_identity(state, &identity, cookie.clone())
                .await
                .map_err(|error| match error {
                    WebError::Unauthorized => login_redirect(&continuation, headers),
                    WebError::TwoFactorRequired => two_factor_redirect(&continuation, headers),
                    error => error_page(error),
                })?;
        super::dashboard::select_shell_organization(
            state,
            cookie.clone(),
            &mut dashboard,
            selected_slug,
        )
        .await
        .map_err(error_page)?;
    }
    Ok(cookie)
}

fn connect_mutation_error(code: ErrorCode, selected_slug: &str, headers: &HeaderMap) -> Response {
    if code == ErrorCode::Unauthenticated {
        login_redirect(&global_settings_path(SETTINGS_PATH, selected_slug), headers)
    } else {
        settings_redirect("request-failed", true, selected_slug, headers)
    }
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
    redirect(format!("{SETTINGS_PATH}?{}", query.finish()), headers)
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "identity-saved" => "Git identity saved.",
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "identity-invalid" => "The Git identity values are too long.",
        "request-failed" => "The settings change could not be completed. Try again.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use askama::Template as _;

    use super::*;
    use crate::{
        templates::SettingsTemplate,
        view::{DashboardView, SettingsData},
    };

    fn dashboard_view() -> DashboardView {
        DashboardView {
            user_name: "Dashboard User".into(),
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
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
            data: SettingsData::default(),
            csrf_token: "csrf".into(),
            message: String::new(),
            error: String::new(),
        };
        let body = SettingsTemplate {
            view: &dashboard_view(),
            settings: &settings,
        }
        .render()
        .expect("render degraded settings");

        assert!(body.contains("Reload before changing it"));
        assert!(body.contains("/settings/"));
        assert!(!body.contains("upstream-sensitive-detail"));
        assert!(!body.contains("/settings/_actions/git-identity"));
    }

    #[test]
    fn retired_account_credential_products_are_absent_from_settings() {
        let settings = SettingsPageView {
            data: SettingsData {
                git_identity_available: true,
                ..Default::default()
            },
            csrf_token: "csrf".into(),
            message: String::new(),
            error: String::new(),
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
        assert!(body.contains("Git identity"));
        assert!(body.contains("/settings/_actions/git-identity"));
    }

    #[test]
    fn global_settings_context_is_query_encoded() {
        assert_eq!(
            global_settings_path(SETTINGS_PATH, "selected org&mode=other"),
            "/settings/?org=selected+org%26mode%3Dother"
        );
    }
}
