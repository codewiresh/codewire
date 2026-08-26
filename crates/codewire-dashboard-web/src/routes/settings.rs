use axum::{
    Form,
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use connectrpc::ErrorCode;
use serde::Deserialize;
use url::Url;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    connect::{
        create_git_credential, delete_git_credential, disconnect_github, ensure_ssh_key,
        regenerate_ssh_key, settings_data, update_git_identity,
    },
    error::WebError,
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    security::{
        canonical_cookie, csrf_cookie, new_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::{SettingsPlaceholderTemplate, SettingsTemplate},
    view::{
        CredentialIdSubmission, CsrfSubmission, GitCredentialSubmission, GitIdentitySubmission,
        SettingsPageView, SettingsPlaceholderView,
    },
};

const SETTINGS_PATH: &str = "/settings/";

#[derive(Debug, Default, Deserialize)]
pub(super) struct SettingsQuery {
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
    let dashboard = match super::dashboard::dashboard_shell_view(&state, &headers).await {
        Ok(view) => view,
        Err(WebError::Unauthorized) => return login_redirect(SETTINGS_PATH, &headers),
        Err(WebError::TwoFactorRequired) => return two_factor_redirect(SETTINGS_PATH, &headers),
        Err(error) => return error_page(error),
    };
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => return login_redirect(SETTINGS_PATH, &headers),
    };
    let data = match settings_data(&state, cookie).await {
        Ok(data) => data,
        Err(WebError::Connect(error)) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(SETTINGS_PATH, &headers);
        }
        Err(error) => return error_page(error),
    };
    let csrf = new_csrf_token();
    let settings = SettingsPageView {
        data,
        csrf_token: csrf.clone(),
        github_connect_url: github_connect_url(&state),
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

pub(super) async fn disconnect_github_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    match disconnect_github(&state, cookie).await {
        Ok(()) => settings_redirect("github-disconnected", false, &headers),
        Err(error) => connect_mutation_error(error.code, &headers),
    }
}

pub(super) async fn create_credential_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GitCredentialSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let host = form.host.trim();
    if name.is_empty()
        || host.is_empty()
        || form.password.is_empty()
        || name.len() > 128
        || host.len() > 253
    {
        return settings_redirect("credential-invalid", true, &headers);
    }
    match create_git_credential(
        &state,
        cookie,
        name.to_owned(),
        host.to_owned(),
        form.username.trim().to_owned(),
        form.password,
    )
    .await
    {
        Ok(()) => settings_redirect("credential-created", false, &headers),
        Err(error) => connect_mutation_error(error.code, &headers),
    }
}

pub(super) async fn delete_credential_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CredentialIdSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if form.credential_id.is_empty() || form.credential_id.len() > 256 {
        return settings_redirect("credential-invalid", true, &headers);
    }
    match delete_git_credential(&state, cookie, form.credential_id).await {
        Ok(()) => settings_redirect("credential-deleted", false, &headers),
        Err(error) => connect_mutation_error(error.code, &headers),
    }
}

pub(super) async fn update_identity_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GitIdentitySubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if form.git_name.len() > 256 || form.git_email.len() > 320 {
        return settings_redirect("identity-invalid", true, &headers);
    }
    match update_git_identity(
        &state,
        cookie,
        form.git_name.trim().to_owned(),
        form.git_email.trim().to_owned(),
    )
    .await
    {
        Ok(()) => settings_redirect("identity-saved", false, &headers),
        Err(error) => connect_mutation_error(error.code, &headers),
    }
}

pub(super) async fn ensure_ssh_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    match ensure_ssh_key(&state, cookie).await {
        Ok(()) => settings_redirect("ssh-created", false, &headers),
        Err(error) => connect_mutation_error(error.code, &headers),
    }
}

pub(super) async fn regenerate_ssh_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    match regenerate_ssh_key(&state, cookie).await {
        Ok(()) => settings_redirect("ssh-regenerated", false, &headers),
        Err(error) => connect_mutation_error(error.code, &headers),
    }
}

pub(super) async fn security(State(state): State<AppState>, headers: HeaderMap) -> Response {
    placeholder(
        &state,
        &headers,
        SettingsPlaceholderView {
            title: "Security settings",
            heading: "Security settings",
            description: "Two-factor authentication and password controls.",
            user_name: String::new(),
            email: String::new(),
            show_profile: false,
        },
    )
    .await
}

pub(super) async fn sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    placeholder(
        &state,
        &headers,
        SettingsPlaceholderView {
            title: "Active sessions",
            heading: "Active sessions",
            description: "Review sessions attached to your account.",
            user_name: String::new(),
            email: String::new(),
            show_profile: false,
        },
    )
    .await
}

async fn placeholder(
    state: &AppState,
    headers: &HeaderMap,
    mut view: SettingsPlaceholderView,
) -> Response {
    let identity = match authenticated_identity(state, headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return login_redirect(SETTINGS_PATH, headers),
        Err(error) => return error_page(error),
    };
    if enforce_two_factor(&identity).is_err() {
        return two_factor_redirect(SETTINGS_PATH, headers);
    }
    view.user_name = identity.display_name().to_owned();
    view.email = identity.email().to_owned();
    render_page(SettingsPlaceholderTemplate { view: &view })
}

async fn mutation_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<axum::http::HeaderValue, Response> {
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| match error {
            WebError::Unauthorized => login_redirect(SETTINGS_PATH, headers),
            error => error_page(error),
        })?;
    if enforce_two_factor(&identity).is_err() {
        return Err(two_factor_redirect(SETTINGS_PATH, headers));
    }
    if !request_has_same_origin(headers, &state.public_origin) || !valid_csrf_token(headers, csrf) {
        return Err(error_page(WebError::CsrfRejected));
    }
    canonical_cookie(headers).map_err(|()| login_redirect(SETTINGS_PATH, headers))
}

fn connect_mutation_error(code: ErrorCode, headers: &HeaderMap) -> Response {
    if code == ErrorCode::Unauthenticated {
        login_redirect(SETTINGS_PATH, headers)
    } else {
        settings_redirect("request-failed", true, headers)
    }
}

fn settings_redirect(code: &str, error: bool, headers: &HeaderMap) -> Response {
    let key = if error { "error" } else { "message" };
    redirect(
        format!(
            "{SETTINGS_PATH}?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair(key, code)
                .finish()
        ),
        headers,
    )
}

fn github_connect_url(state: &AppState) -> String {
    let mut url = Url::parse(&format!(
        "{}/api/v1/github/oauth/authorize",
        state.browser_api_origin
    ))
    .expect("validated API origin");
    url.query_pairs_mut()
        .append_pair("return_url", &format!("{}/settings/", state.public_origin));
    url.into()
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "github-disconnected" => "GitHub was disconnected.",
        "credential-created" => "Git credential saved.",
        "credential-deleted" => "Git credential deleted.",
        "identity-saved" => "Git identity saved.",
        "ssh-created" => "SSH key created.",
        "ssh-regenerated" => "SSH key regenerated. The old key no longer works.",
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "credential-invalid" => "Enter a name, host, and token or password.",
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

    type SettingsOutage = (&'static str, fn(&mut SettingsData), &'static str);

    fn dashboard_view() -> DashboardView {
        DashboardView {
            user_name: "Dashboard User".into(),
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
            github_connected: false,
            github_available: false,
            show_checklist: false,
            new_organization_url: "/organizations/new/".into(),
            settings_url: SETTINGS_PATH.into(),
            github_connect_url: String::new(),
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
        let outages: [SettingsOutage; 4] = [
            (
                "github",
                |data| data.github_available = false,
                "Other settings remain usable",
            ),
            (
                "credentials",
                |data| data.credentials_available = false,
                "You can still add a credential",
            ),
            (
                "identity",
                |data| data.git_identity_available = false,
                "Reload before changing it",
            ),
            (
                "ssh",
                |data| data.ssh_key_status_available = false,
                "Reload before changing it",
            ),
        ];

        for (name, inject, notice) in outages {
            let mut data = SettingsData {
                github_available: true,
                credentials_available: true,
                git_identity_available: true,
                ssh_key_status_available: true,
                ..Default::default()
            };
            inject(&mut data);
            let settings = SettingsPageView {
                data,
                csrf_token: "csrf".into(),
                github_connect_url: "/github/connect".into(),
                message: String::new(),
                error: String::new(),
            };
            let body = SettingsTemplate {
                view: &dashboard_view(),
                settings: &settings,
            }
            .render()
            .expect("render degraded settings");

            assert!(body.contains(notice), "{name}");
            assert!(body.contains("/settings/"), "{name}");
            assert!(
                body.contains("/settings/_actions/credentials/create"),
                "{name}"
            );
            assert!(!body.contains("upstream-sensitive-detail"), "{name}");
            if name == "identity" {
                assert!(!body.contains("/settings/_actions/git-identity"));
            }
            if name == "ssh" {
                assert!(!body.contains("/settings/_actions/ssh/ensure"));
                assert!(!body.contains("/settings/_actions/ssh/regenerate"));
            }
            if name == "github" {
                assert!(!body.contains("/settings/_actions/github/disconnect"));
                assert!(!body.contains("/github/connect"));
            }
        }
    }
}
