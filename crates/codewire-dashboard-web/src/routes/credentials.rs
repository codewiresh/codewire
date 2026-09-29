use std::convert::Infallible;

use axum::{
    Form,
    body::{Body, Bytes},
    extract::{FromRequestParts, Query, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::Response,
};
use chrono::{NaiveDateTime, Utc};
use codewire_access::AccessProfileName;
use codewire_proto::codewire::v1::AccessProfileEntry;
use connectrpc::ErrorCode;
use serde::Deserialize;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};
use url::Url;

use crate::{
    connect::{settings_data as git_identity_data, update_git_identity},
    credentials_connect,
    environment_drafts::DraftReturn,
    environment_source_forms::exact_id,
    error::WebError,
    response::{
        error_page, login_redirect, redirect, render_credential_settings_page, two_factor_redirect,
    },
    security::{
        GitHubAppNavigation, canonical_cookie, clear_github_app_authorization_cookie, csrf_cookie,
        github_app_authorization_continuation, github_app_authorization_cookie, new_csrf_token,
        page_csrf_token, with_csrf_cookie, with_response_cookie,
    },
    state::AppState,
    templates::CredentialSettingsTemplate,
    view::{
        CredentialApiKeySubmission, CredentialOAuthSubmission, CredentialProfileCreateSubmission,
        CredentialProfileDeleteSubmission, CredentialProfileUpdateSubmission,
        CredentialRenameSubmission, CredentialRevisionSubmission, CredentialRotateSubmission,
        CredentialSettingsView, CredentialSshGenerateSubmission, CredentialSshImportSubmission,
        GitHubAppAuthorizationSubmission, GitIdentitySubmission,
    },
};

const PATH: &str = "/settings/credentials/";
pub(super) const GITHUB_APP_CALLBACK_PATH: &str = "/api/v1/github/oauth/callback";

#[derive(Debug, Default, Deserialize)]
pub(super) struct QueryParameters {
    #[serde(skip)]
    draft: DraftReturn,
    #[serde(default)]
    org: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    dialog: String,
}

// Navigation is parsed independently of authority-bearing query fields. An
// invalid or repeated draft handle must not reject an otherwise valid action.
pub(super) struct CredentialQuery(QueryParameters);

impl<S: Send + Sync> FromRequestParts<S> for CredentialQuery {
    type Rejection = axum::extract::rejection::QueryRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let RawQuery(raw) = RawQuery::from_request_parts(parts, state)
            .await
            .expect("RawQuery is infallible");
        let Query(mut query) = Query::<QueryParameters>::from_request_parts(parts, state).await?;
        query.draft = match DraftReturn::parse(raw.as_deref()) {
            exact @ DraftReturn::Exact(_) => exact,
            _ => DraftReturn::NoRequest,
        };
        Ok(Self(query))
    }
}

// Do not derive Debug: a callback code is short-lived authorization material
// and must not enter route diagnostics or a query rejection report.
#[derive(Default, Deserialize)]
pub(super) struct GitHubAppCallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    CredentialQuery(query): CredentialQuery,
) -> Response {
    let continuation = page_path(&query);
    let dashboard =
        match super::dashboard::personal_settings_shell_view(&state, &headers, &query.org).await {
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
    let git_identity = match git_identity_data(&state, cookie.clone()).await {
        Ok(identity) => identity,
        Err(WebError::Connect(error)) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&continuation, &headers);
        }
        Err(error) => return error_page(error),
    };
    let data = match credentials_connect::settings_data(&state, cookie).await {
        Ok(data) => data,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&continuation, &headers);
        }
        Err(error) => return error_page(WebError::Connect(error)),
    };
    let csrf = page_csrf_token(&headers);
    let page = CredentialSettingsView {
        navigation_query: page_query(&query),
        creation_return_url: if dashboard.has_selected_organization {
            if let DraftReturn::Exact(id) = &query.draft {
                format!(
                    "/{}/new/?creation_draft={id}",
                    dashboard.selected_organization_slug
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        },
        git_identity,
        git_identity_feedback: query.message == "identity-saved"
            || matches!(
                query.error.as_str(),
                "identity-invalid" | "identity-request-failed"
            ),
        active_dialog: approved_dialog(&query.dialog, &data),
        github_install_url: github_app_installation_url(&state.github_app_slug),
        credentials: data.credentials,
        profiles: data.profiles,
        choices: data.choices,
        csrf_token: csrf.clone(),
        message: approved_message(&query.message).into(),
        error: approved_error(&query.error).into(),
    };
    with_csrf_cookie(
        render_credential_settings_page(CredentialSettingsTemplate {
            view: &dashboard,
            page: &page,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

pub(super) async fn update_identity_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    form: Result<Form<GitIdentitySubmission>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return git_identity_redirect("identity-invalid", true, &query, &headers);
    };
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if form.git_name.len() > 256 || form.git_email.len() > 320 {
        return git_identity_redirect("identity-invalid", true, &query, &headers);
    }
    match update_git_identity(
        &state,
        cookie,
        form.git_name.trim().into(),
        form.git_email.trim().into(),
    )
    .await
    {
        Ok(()) => git_identity_redirect("identity-saved", false, &query, &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(&page_path(&query), &headers)
        }
        Err(_) => git_identity_redirect("identity-request-failed", true, &query, &headers),
    }
}

fn git_identity_redirect(
    code: &str,
    error: bool,
    context: &QueryParameters,
    headers: &HeaderMap,
) -> Response {
    let target = page_feedback_target(context, if error { "error" } else { "message" }, code, "");
    redirect(format!("{target}#git-identity"), headers)
}

pub(super) async fn create_profile_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileCreateSubmission>,
) -> Response {
    let dialog = "create-profile";
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    if !valid_name(name) {
        return page_error_redirect("profile-invalid", dialog, &query, &headers);
    }
    let entries = match entries(form.codex, form.openai, form.anthropic, form.ssh) {
        Ok(entries) => entries,
        Err(()) => return page_error_redirect("profile-invalid", dialog, &query, &headers),
    };
    match credentials_connect::create_profile(&state, cookie, name.into(), entries).await {
        Ok(()) => page_redirect("profile-created", false, &query, &headers),
        Err(error) => mutation_error(error.code, false, dialog, &query, &headers),
    }
}

pub(super) async fn update_profile_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileUpdateSubmission>,
) -> Response {
    let dialog = row_action_dialog("profile", &form.profile_id, "edit");
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.profile_id).is_err() || !valid_revision(form.expected_revision) {
        return page_error_redirect("profile-invalid", &dialog, &query, &headers);
    }
    let entries = match entries(form.codex, form.openai, form.anthropic, form.ssh) {
        Ok(entries) => entries,
        Err(()) => return page_error_redirect("profile-invalid", &dialog, &query, &headers),
    };
    match credentials_connect::update_profile(
        &state,
        cookie,
        form.profile_id,
        form.expected_revision,
        entries,
    )
    .await
    {
        Ok(()) => page_redirect("profile-updated", false, &query, &headers),
        Err(error) => mutation_error(error.code, false, &dialog, &query, &headers),
    }
}

pub(super) async fn delete_profile_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileDeleteSubmission>,
) -> Response {
    let dialog = row_action_dialog("profile", &form.profile_id, "delete");
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.profile_id).is_err() || !valid_revision(form.expected_revision) {
        return page_error_redirect("profile-invalid", &dialog, &query, &headers);
    }
    match credentials_connect::delete_profile(
        &state,
        cookie,
        form.profile_id,
        form.expected_revision,
    )
    .await
    {
        Ok(()) => page_redirect("profile-deleted", false, &query, &headers),
        Err(error) => mutation_error(error.code, true, &dialog, &query, &headers),
    }
}

pub(super) async fn add_api_key_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialApiKeySubmission>,
) -> Response {
    let dialog = match form.provider.as_str() {
        "openai" => "add-openai-api-key",
        "anthropic" => "add-anthropic-api-key",
        _ => "add-credential",
    };
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let value = form.value.into_bytes();
    let expiry = parse_expiration_utc(&form.expiration_utc);
    if !matches!(form.provider.as_str(), "openai" | "anthropic")
        || !valid_credential_name(name)
        || value.is_empty()
        || value.len() > 1024
        || expiry.is_err()
    {
        return page_error_redirect("credential-invalid", dialog, &query, &headers);
    }
    match credentials_connect::add_api_key(
        &state,
        cookie,
        form.provider,
        name.into(),
        value,
        expiry.expect("checked above"),
    )
    .await
    {
        Ok(()) => page_redirect("credential-added", false, &query, &headers),
        Err(error) => credential_mutation_error(error.code, false, dialog, &query, &headers),
    }
}

pub(super) async fn generate_ssh_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialSshGenerateSubmission>,
) -> Response {
    let dialog = "generate-ssh";
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let expiry = parse_expiration_utc(&form.expiration_utc);
    if !valid_credential_name(name) || expiry.is_err() {
        return page_error_redirect("credential-invalid", dialog, &query, &headers);
    }
    match credentials_connect::generate_ssh(
        &state,
        cookie,
        name.into(),
        expiry.expect("checked above"),
    )
    .await
    {
        Ok(()) => page_redirect("credential-generated", false, &query, &headers),
        Err(error) => credential_mutation_error(error.code, false, dialog, &query, &headers),
    }
}

pub(super) async fn import_ssh_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialSshImportSubmission>,
) -> Response {
    let dialog = "import-ssh";
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let private_key = form.private_key.into_bytes();
    let passphrase = if form.passphrase.is_empty() {
        None
    } else {
        Some(form.passphrase.into_bytes())
    };
    let expiry = parse_expiration_utc(&form.expiration_utc);
    if !valid_credential_name(name)
        || private_key.is_empty()
        || private_key.len() > 64 * 1024
        || passphrase.as_ref().is_some_and(|value| {
            value.len() > 1024 || value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        })
        || expiry.is_err()
    {
        return page_error_redirect("credential-invalid", dialog, &query, &headers);
    }
    match credentials_connect::import_ssh(
        &state,
        cookie,
        name.into(),
        private_key,
        passphrase,
        expiry.expect("checked above"),
    )
    .await
    {
        Ok(()) => page_redirect("credential-imported", false, &query, &headers),
        Err(error) => credential_mutation_error(error.code, false, dialog, &query, &headers),
    }
}

pub(super) async fn rename_credential_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialRenameSubmission>,
) -> Response {
    let dialog = row_action_dialog("credential", &form.credential_id, "rename");
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    if exact_id(&form.credential_id).is_err()
        || !valid_generation(form.expected_revocation_generation, false)
        || !valid_credential_name(&form.expected_name)
        || !valid_credential_name(name)
    {
        return page_error_redirect("credential-invalid", &dialog, &query, &headers);
    }
    match credentials_connect::rename_credential(
        &state,
        cookie,
        form.credential_id,
        form.expected_revocation_generation,
        form.expected_name,
        name.into(),
    )
    .await
    {
        Ok(()) => page_redirect("credential-renamed", false, &query, &headers),
        Err(error) => credential_mutation_error(error.code, false, &dialog, &query, &headers),
    }
}

pub(super) async fn rotate_api_key_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialRotateSubmission>,
) -> Response {
    let dialog = row_action_dialog("credential", &form.credential_id, "rotate");
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let value = form.value.into_bytes();
    let expiry = parse_expiration_utc(&form.expiration_utc);
    if exact_id(&form.credential_id).is_err()
        || !valid_generation(form.expected_revocation_generation, true)
        || value.is_empty()
        || value.len() > 1024
        || expiry.is_err()
    {
        return page_error_redirect("credential-invalid", &dialog, &query, &headers);
    }
    match credentials_connect::rotate_api_key(
        &state,
        cookie,
        form.credential_id,
        form.expected_revocation_generation,
        value,
        expiry.expect("checked above"),
    )
    .await
    {
        Ok(()) => page_redirect("credential-rotated", false, &query, &headers),
        Err(error) => credential_mutation_error(error.code, false, &dialog, &query, &headers),
    }
}

pub(super) async fn revoke_credential_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialRevisionSubmission>,
) -> Response {
    credential_revision_action(state, query, headers, form, false).await
}

pub(super) async fn delete_credential_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialRevisionSubmission>,
) -> Response {
    credential_revision_action(state, query, headers, form, true).await
}

/// Start browser-only GitHub App authorization, not the device-code flow used
/// by `cw`. An explicit configured callback selects this dashboard even when
/// the App registration has several callbacks for local and hosted instances.
pub(super) async fn github_app_authorize_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<GitHubAppAuthorizationSubmission>,
) -> Response {
    let dialog = if form.credential_id.is_empty() {
        "connect-github".to_owned()
    } else {
        row_action_dialog("credential", &form.credential_id, "reconnect")
    };
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if state.github_app_slug.is_empty() || state.github_app_client_id.is_empty() {
        return page_error_redirect("github-app-unavailable", &dialog, &query, &headers);
    }
    let reconnect = match (
        form.credential_id.is_empty(),
        form.expected_revocation_generation,
    ) {
        (true, None) => (None, None),
        (false, Some(generation))
            if exact_id(&form.credential_id).is_ok()
                && valid_generation(generation, true)
                && form.confirm_reconnect == "yes" =>
        {
            (Some(form.credential_id), Some(generation))
        }
        _ => return page_error_redirect("credential-invalid", &dialog, &query, &headers),
    };
    if let (Some(credential_id), Some(generation)) = (&reconnect.0, reconnect.1)
        && let Err(error) = credentials_connect::validate_github_app_reconnect(
            &state,
            cookie.clone(),
            credential_id,
            generation,
        )
        .await
    {
        return credential_mutation_error(error.code, false, &dialog, &query, &headers);
    }
    // This is navigation for a personal provider connection, not a grant.
    // A failed optional lookup must not prevent a valid connection/reconnect.
    let navigation = if query.org.is_empty() {
        None
    } else {
        super::dashboard::dashboard_shell_view(&state, &headers)
            .await
            .ok()
            .and_then(|view| {
                view.organizations
                    .iter()
                    .find(|org| org.slug == query.org)
                    .map(|org| GitHubAppNavigation {
                        organization_id: org.id.clone(),
                        draft_id: match &query.draft {
                            DraftReturn::Exact(id) => Some(id.clone()),
                            _ => None,
                        },
                    })
            })
    };
    let callback_state = new_csrf_token();
    let callback_cookie = match github_app_authorization_cookie(
        &state.public_origin,
        &callback_state,
        &cookie,
        reconnect.0.as_deref(),
        reconnect.1,
        navigation.as_ref(),
    ) {
        Some(cookie) => cookie,
        None => return page_error_redirect("credential-invalid", &dialog, &query, &headers),
    };
    with_response_cookie(
        redirect(
            github_app_authorization_url(
                &state.github_app_client_id,
                &state.public_origin,
                &callback_state,
            ),
            &headers,
        ),
        callback_cookie,
    )
}

/// Finish a GitHub App authorization callback. The authenticated session and
/// one-use browser state fence this cross-site GET; it intentionally does not
/// require same-origin form CSRF because GitHub performs the redirect.
pub(super) async fn github_app_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<GitHubAppCallbackQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let context = QueryParameters::default();
    let continuation = page_path(&context);
    let clear = clear_github_app_authorization_cookie(&state.public_origin);
    let dashboard = match super::dashboard::personal_settings_shell_view(&state, &headers, "").await
    {
        Ok(view) => view,
        Err(WebError::Unauthorized) => {
            return github_app_callback_response(login_redirect(&continuation, &headers), clear);
        }
        Err(WebError::TwoFactorRequired) => {
            return github_app_callback_response(
                two_factor_redirect(&continuation, &headers),
                clear,
            );
        }
        Err(error) => return github_app_callback_response(error_page(error), clear),
    };
    let cookie = match canonical_cookie(&headers) {
        Ok(cookie) => cookie,
        Err(()) => {
            return github_app_callback_response(login_redirect(&continuation, &headers), clear);
        }
    };
    let Ok(Query(query)) = query else {
        return github_app_callback_response(
            page_error_redirect("github-app-failed", "connect-github", &context, &headers),
            clear,
        );
    };
    // Validate the authorization core before optional navigation. Never accept
    // an organization, slug, or return URL from callback query parameters.
    let callback = match github_app_authorization_continuation(&headers, &query.state, &cookie) {
        Some(callback) => callback,
        None => {
            return github_app_callback_response(
                page_error_redirect("github-app-failed", "connect-github", &context, &headers),
                clear,
            );
        }
    };
    let context = callback
        .navigation
        .as_ref()
        .and_then(|nav| {
            dashboard
                .organizations
                .iter()
                .find(|org| org.id == nav.organization_id)
                .map(|org| QueryParameters {
                    org: org.slug.clone(),
                    draft: nav
                        .draft_id
                        .as_ref()
                        .map_or(DraftReturn::NoRequest, |id| DraftReturn::Exact(id.clone())),
                    ..Default::default()
                })
        })
        .unwrap_or_default();
    let dialog = callback
        .credential_id
        .as_deref()
        .map(|id| row_action_dialog("credential", id, "reconnect"))
        .filter(|dialog| !dialog.is_empty())
        .unwrap_or_else(|| "connect-github".to_owned());
    let response = if !query.error.is_empty() {
        page_error_redirect("github-app-cancelled", &dialog, &context, &headers)
    } else if !valid_github_app_callback_code(&query.code) {
        page_error_redirect("github-app-failed", &dialog, &context, &headers)
    } else {
        match credentials_connect::complete_github_app_authorization(
            &state,
            cookie,
            query.code.into_bytes(),
            callback.credential_id,
            callback.expected_generation,
        )
        .await
        {
            Ok(()) => page_redirect("github-app-connected", false, &context, &headers),
            Err(error) if error.code == ErrorCode::AlreadyExists => {
                page_error_redirect("github-app-already-connected", &dialog, &context, &headers)
            }
            Err(error) => {
                if let Some(feedback) = credentials_connect::github_authorization_feedback(&error) {
                    page_error_redirect(feedback, &dialog, &context, &headers)
                } else {
                    credential_mutation_error(error.code, false, &dialog, &context, &headers)
                }
            }
        }
    };
    // The callback returns without organization parameters; the organization
    // its signed navigation named becomes the remembered one.
    let response =
        super::remember_organization_choice(response, &state.public_origin, &context.org);
    github_app_callback_response(response, clear)
}

fn github_app_installation_url(app_slug: &str) -> String {
    if app_slug.is_empty() {
        return String::new();
    }
    let mut target = Url::parse("https://github.com").expect("static GitHub origin");
    target.set_path(&format!("/apps/{app_slug}/installations/new"));
    target.into()
}

fn github_app_authorization_url(
    client_id: &str,
    public_origin: &str,
    callback_state: &str,
) -> String {
    let mut target = Url::parse("https://github.com/login/oauth/authorize")
        .expect("static GitHub authorization URL");
    // Both values come from validated server configuration, never Host,
    // Forwarded headers, query parameters or the submitted form. The broker
    // must exchange the code using this same registered callback URL.
    target
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair(
            "redirect_uri",
            &format!("{public_origin}{GITHUB_APP_CALLBACK_PATH}"),
        )
        .append_pair("state", callback_state);
    target.into()
}

fn valid_github_app_callback_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn github_app_callback_response(mut response: Response, clear_cookie: String) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    with_response_cookie(response, clear_cookie)
}

pub(super) async fn enroll_oauth_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialOAuthSubmission>,
) -> Response {
    let dialog = if form.credential_id.is_empty() {
        match form.provider.as_str() {
            "codex" => "connect-codex".to_owned(),
            _ => String::new(),
        }
    } else {
        row_action_dialog("credential", &form.credential_id, "reconnect")
    };
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let Some(provider) = web_device_oauth_provider(&form.provider) else {
        return page_error_redirect("credential-invalid", &dialog, &query, &headers);
    };
    let name = form.name.trim();
    let reconnect = match (
        form.credential_id.is_empty(),
        form.expected_revocation_generation,
    ) {
        (true, None) => (None, None),
        (false, Some(generation))
            if exact_id(&form.credential_id).is_ok()
                && valid_generation(generation, true)
                && form.confirm_reconnect == "yes" =>
        {
            (Some(form.credential_id), Some(generation))
        }
        _ => return page_error_redirect("credential-invalid", &dialog, &query, &headers),
    };
    if !valid_oauth_name(name) {
        return page_error_redirect("credential-invalid", &dialog, &query, &headers);
    }

    let (events, receiver) = tokio::sync::mpsc::channel(2);
    let request = credentials_connect::OAuthEnrollmentRequest {
        provider,
        name: name.into(),
        credential_id: reconnect.0,
        expected_generation: reconnect.1,
    };
    tokio::spawn(credentials_connect::run_oauth_enrollment(
        state, cookie, request, events,
    ));
    if wants_enrollment_events(&headers) {
        enrollment_events(receiver, &query)
    } else {
        enrollment_response(receiver, &query)
    }
}

/// The Credentials dialog asks for the enrollment as events so the whole
/// device authorization stays in the dialog; a plain form post gets the
/// streamed fallback page.
fn wants_enrollment_events(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|kind| kind.trim().starts_with("text/event-stream"))
        })
}

fn enrollment_events(
    receiver: tokio::sync::mpsc::Receiver<credentials_connect::OAuthEnrollmentEvent>,
    context: &QueryParameters,
) -> Response {
    let connected = page_feedback_target(context, "message", "credential-connected", "");
    let stream = ReceiverStream::new(receiver).map(move |event| {
        Ok::<Bytes, Infallible>(Bytes::from(enrollment_event_frame(event, &connected)))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(stream))
        .expect("static enrollment event headers")
}

fn enrollment_event_frame(
    event: credentials_connect::OAuthEnrollmentEvent,
    connected: &str,
) -> String {
    use credentials_connect::OAuthEnrollmentEvent as Event;
    let (name, data) = match event {
        Event::Challenge {
            provider,
            verification_url,
            user_code,
            expires_utc,
        } => (
            "challenge",
            serde_json::json!({
                "provider": provider,
                "verificationUrl": verification_url,
                "userCode": user_code,
                "expires": expires_utc,
            }),
        ),
        Event::Committed => ("connected", serde_json::json!({ "location": connected })),
        Event::Failed { reason, uncertain } => (
            "failed",
            serde_json::json!({
                "message": enrollment_failure_message(reason),
                "uncertain": uncertain,
            }),
        ),
    };
    format!("event: {name}\ndata: {data}\n\n")
}

fn enrollment_failure_message(reason: credentials_connect::OAuthEnrollmentFailure) -> &'static str {
    use credentials_connect::OAuthEnrollmentFailure as Failure;
    match reason {
        Failure::SignInRequired => {
            "Your session ended. Sign in again, then connect from Credentials."
        }
        Failure::Unavailable => {
            "The credential service is busy or unavailable. Try again in a moment."
        }
        Failure::AlreadyExists => {
            "A credential with this name already exists. No credential was overwritten; choose another name or reconnect the existing one."
        }
        Failure::Changed => {
            "This credential changed while connecting. Open it in Credentials and reconnect."
        }
        Failure::Unsupported => {
            "Codewire could not verify the provider's response. Try again; if it fails again, contact support."
        }
        Failure::Invalid => "That connection request was not valid. Start again from Credentials.",
        Failure::NotCompleted => "Sign-in was not completed. Start again to get a new code.",
        Failure::Expired => {
            "The code expired before it was approved. Start again to get a new code."
        }
        Failure::Cancelled => "Connection cancelled.",
        Failure::UnexpectedResponse => {
            "Codewire did not get a final answer from the provider, so the connection may or may not have been saved."
        }
    }
}

const ENROLLMENT_UNCERTAIN: &str =
    "It may already be saved. Check Credentials before connecting again.";

fn enrollment_response(
    receiver: tokio::sync::mpsc::Receiver<credentials_connect::OAuthEnrollmentEvent>,
    context: &QueryParameters,
) -> Response {
    // Without JavaScript the form lands here. The page streams each step; CSS
    // hides a step once the next one has arrived.
    let return_path = escape_html(&page_path(context));
    let prefix = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Connect credential · Codewire</title>\
<link rel=\"stylesheet\" href=\"/assets/codewire/design-v1.css\">\
<link rel=\"stylesheet\" href=\"/assets/codewire/routes/dashboard-v1.css\">\
<link rel=\"stylesheet\" href=\"/assets/codewire/routes/settings-v1.css\">\
</head><body class=\"cw-body\"><div data-dashboard-app><main class=\"cw-connect\">\
<section class=\"cw-card cw-connect-panel\" aria-labelledby=\"credential-enrollment-title\">\
<header class=\"cw-card-header\"><a class=\"cw-connect-back\" href=\"{return_path}\">Credentials</a>\
<h1 id=\"credential-enrollment-title\" class=\"cw-card-title\">Connect credential</h1></header>\
<div class=\"cw-card-content\"><p class=\"cw-device-status\" data-connect-pending>Requesting a sign-in code…</p>"
    );
    let stream = tokio_stream::iter([Ok::<Bytes, Infallible>(Bytes::from(prefix))]).chain(
        ReceiverStream::new(receiver)
            .map(move |event| Ok(Bytes::from(render_enrollment_event(event, &return_path)))),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .header(header::PRAGMA, "no-cache")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header("x-accel-buffering", "no")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'",
        )
        .body(Body::from_stream(stream))
        .expect("static enrollment response headers")
}

fn render_enrollment_event(
    event: credentials_connect::OAuthEnrollmentEvent,
    return_path: &str,
) -> String {
    const CLOSE: &str = "</div></section></main></div></body></html>";
    match event {
        credentials_connect::OAuthEnrollmentEvent::Challenge {
            provider,
            verification_url,
            user_code,
            expires_utc,
        } => format!(
            "<div class=\"cw-device-enrollment\" data-connect-challenge><p>Enter this code in {provider} to approve the connection.</p><p class=\"cw-device-code\"><code>{code}</code></p><a class=\"cw-button\" href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">Open {provider}</a><p class=\"cw-device-status\">Waiting for approval. The code expires at {expires}.</p></div>",
            provider = escape_html(provider),
            url = escape_html(&verification_url),
            code = escape_html(&user_code),
            expires = escape_html(&expires_utc),
        ),
        credentials_connect::OAuthEnrollmentEvent::Committed => format!(
            "<div class=\"cw-device-enrollment\" data-connect-result><p class=\"cw-alert cw-alert--success\" role=\"status\">Credential connected.</p><a class=\"cw-button\" href=\"{return_path}\">Back to Credentials</a></div>{CLOSE}"
        ),
        credentials_connect::OAuthEnrollmentEvent::Failed { reason, uncertain } => {
            let message = enrollment_failure_message(reason);
            let uncertain = if uncertain {
                format!("<p class=\"cw-device-status\">{ENROLLMENT_UNCERTAIN}</p>")
            } else {
                String::new()
            };
            format!(
                "<div class=\"cw-device-enrollment\" data-connect-result><p class=\"cw-alert cw-alert--error\" role=\"alert\">{message}</p>{uncertain}<a class=\"cw-button\" href=\"{return_path}\">Back to Credentials</a></div>{CLOSE}"
            )
        }
    }
}

fn valid_oauth_name(name: &str) -> bool {
    valid_credential_name(name)
}

// Device authorization is intentionally browser-only for Codex. GitHub's
// browser path is the dedicated GitHub App authorization route above; `cw`
// keeps its separate GitHub device-code RPC in credential-service.
fn web_device_oauth_provider(value: &str) -> Option<credentials_connect::OAuthProvider> {
    (value == "codex").then_some(credentials_connect::OAuthProvider::Codex)
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

async fn credential_revision_action(
    state: AppState,
    query: QueryParameters,
    headers: HeaderMap,
    form: CredentialRevisionSubmission,
    delete: bool,
) -> Response {
    let dialog = row_action_dialog(
        "credential",
        &form.credential_id,
        if delete { "delete" } else { "revoke" },
    );
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.credential_id).is_err()
        || !valid_generation(form.expected_revocation_generation, !delete)
    {
        return page_error_redirect("credential-invalid", &dialog, &query, &headers);
    }
    let result = if delete {
        credentials_connect::delete_credential(
            &state,
            cookie,
            form.credential_id,
            form.expected_revocation_generation,
        )
        .await
    } else {
        credentials_connect::revoke_credential(
            &state,
            cookie,
            form.credential_id,
            form.expected_revocation_generation,
        )
        .await
    };
    match result {
        Ok(()) => page_redirect(
            if delete {
                "credential-deleted"
            } else {
                "credential-revoked"
            },
            false,
            &query,
            &headers,
        ),
        Err(error) => credential_mutation_error(error.code, delete, &dialog, &query, &headers),
    }
}

async fn mutation_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    context: &QueryParameters,
) -> Result<axum::http::HeaderValue, Response> {
    super::settings::mutation_cookie_with_continuation(state, headers, csrf, &page_path(context))
        .await
}

fn entries(
    codex: String,
    openai: String,
    anthropic: String,
    ssh: String,
) -> Result<Vec<AccessProfileEntry>, ()> {
    let mut entries = Vec::new();
    for (slot, credential_id) in [
        ("codex", codex),
        ("openai", openai),
        ("anthropic", anthropic),
        ("ssh", ssh),
    ] {
        if credential_id.is_empty() {
            continue;
        }
        exact_id(&credential_id)?;
        entries.push(AccessProfileEntry {
            capability_slot: slot.into(),
            credential_id,
            ..Default::default()
        });
    }
    Ok(entries)
}

fn valid_name(name: &str) -> bool {
    AccessProfileName::parse(name).is_ok()
}

fn valid_credential_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.bytes().any(|byte| byte.is_ascii_control())
}

fn parse_expiration_utc(value: &str) -> Result<Option<u64>, ()> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let timestamp = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M")
        .map_err(|_| ())?
        .and_utc()
        .timestamp();
    if timestamp <= Utc::now().timestamp() {
        return Err(());
    }
    u64::try_from(timestamp).map(Some).map_err(|_| ())
}

fn valid_revision(revision: u64) -> bool {
    revision > 0 && revision < i64::MAX as u64
}

fn valid_generation(generation: u64, increments: bool) -> bool {
    generation > 0
        && if increments {
            generation < i64::MAX as u64
        } else {
            generation <= i64::MAX as u64
        }
}

fn mutation_error(
    code: ErrorCode,
    delete: bool,
    dialog: &str,
    context: &QueryParameters,
    headers: &HeaderMap,
) -> Response {
    if code == ErrorCode::Unauthenticated {
        return login_redirect(&page_path(context), headers);
    }
    page_error_redirect(mutation_error_code(code, delete), dialog, context, headers)
}

fn credential_mutation_error(
    code: ErrorCode,
    delete: bool,
    dialog: &str,
    context: &QueryParameters,
    headers: &HeaderMap,
) -> Response {
    if code == ErrorCode::Unauthenticated {
        return login_redirect(&page_path(context), headers);
    }
    let error = if matches!(
        code,
        ErrorCode::Aborted | ErrorCode::AlreadyExists | ErrorCode::NotFound
    ) {
        "credential-conflict"
    } else if delete && code == ErrorCode::FailedPrecondition {
        "credential-in-use"
    } else if matches!(
        code,
        ErrorCode::InvalidArgument | ErrorCode::FailedPrecondition | ErrorCode::PermissionDenied
    ) {
        "credential-request-failed"
    } else {
        // Any transport/protocol failure can lose a successful publication
        // acknowledgement. Never encourage an automatic or blind retry.
        "credential-uncertain"
    };
    page_error_redirect(error, dialog, context, headers)
}

fn mutation_error_code(code: ErrorCode, delete: bool) -> &'static str {
    if code == ErrorCode::InvalidArgument {
        "profile-invalid"
    } else if code == ErrorCode::Aborted || code == ErrorCode::AlreadyExists {
        "profile-conflict"
    } else if delete && code == ErrorCode::FailedPrecondition {
        "profile-in-use"
    } else {
        "request-failed"
    }
}

fn navigation_query(context: &QueryParameters) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if let DraftReturn::Exact(id) = &context.draft {
        query.append_pair("creation_draft", id);
    }
    query.finish()
}

fn page_query(context: &QueryParameters) -> String {
    let query = navigation_query(context);
    if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    }
}

fn page_path(context: &QueryParameters) -> String {
    format!("{PATH}{}", page_query(context))
}

fn page_feedback_target(context: &QueryParameters, key: &str, code: &str, dialog: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(navigation_query(context));
    query.append_pair(key, code);
    if !dialog.is_empty() {
        query.append_pair("dialog", dialog);
    }
    format!("{PATH}?{}", query.finish())
}

fn page_redirect(
    code: &str,
    error: bool,
    context: &QueryParameters,
    headers: &HeaderMap,
) -> Response {
    redirect(
        page_feedback_target(context, if error { "error" } else { "message" }, code, ""),
        headers,
    )
}

// Dialog destinations are presentation state, not selectors or return URLs.
// Row dialogs must resolve against the freshly authenticated, owner-scoped
// catalog. A stale/deleted identity leaves its static error on the page.
fn row_dialog(kind: &str, id: &str) -> String {
    if matches!(kind, "credential" | "profile") && exact_id(id).is_ok() {
        format!("{kind}-{id}")
    } else {
        String::new()
    }
}

fn row_action_dialog(kind: &str, id: &str, action: &str) -> String {
    let row = row_dialog(kind, id);
    if row.is_empty() || !valid_row_action(kind, action) {
        String::new()
    } else {
        format!("{row}-{action}")
    }
}

fn valid_row_action(kind: &str, action: &str) -> bool {
    match kind {
        "credential" => matches!(
            action,
            "rename" | "reconnect" | "rotate" | "revoke" | "delete"
        ),
        "profile" => matches!(action, "edit" | "delete"),
        _ => false,
    }
}

fn requested_row_id<'a>(requested: &'a str, kind: &str) -> Option<&'a str> {
    let row = requested.strip_prefix(kind)?.strip_prefix('-')?;
    if exact_id(row).is_ok() {
        return Some(row);
    }
    let (id, action) = row.rsplit_once('-')?;
    (exact_id(id).is_ok() && valid_row_action(kind, action)).then_some(id)
}

fn approved_dialog(requested: &str, data: &credentials_connect::CredentialSettingsData) -> String {
    let allowed = matches!(
        requested,
        "add-credential"
            | "connect-github"
            | "connect-codex"
            | "add-openai-api-key"
            | "add-anthropic-api-key"
            | "add-ssh"
            | "generate-ssh"
            | "import-ssh"
            | "create-profile"
    ) || requested_row_id(requested, "credential").is_some_and(|id| {
        data.credentials.iter().any(|credential| {
            credential.id == id
                && (requested == row_dialog("credential", id)
                    || requested == row_action_dialog("credential", id, "rename")
                        && credential.oauth_provider != "github"
                    || requested == row_action_dialog("credential", id, "reconnect")
                        && credential.oauth
                    || requested == row_action_dialog("credential", id, "rotate")
                        && credential.api_key
                    || requested == row_action_dialog("credential", id, "revoke")
                        && !credential.revoked
                        && credential.oauth_provider != "github"
                    || requested == row_action_dialog("credential", id, "delete")
                        && (credential.revoked || credential.oauth_provider == "github"))
        })
    }) || requested_row_id(requested, "profile")
        .is_some_and(|id| data.profiles.iter().any(|profile| profile.id == id));
    if allowed {
        requested.to_owned()
    } else {
        String::new()
    }
}

fn page_error_redirect(
    code: &str,
    dialog: &str,
    context: &QueryParameters,
    headers: &HeaderMap,
) -> Response {
    redirect(
        page_feedback_target(context, "error", code, dialog),
        headers,
    )
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "identity-saved" => "Git commit identity saved.",
        "credential-added" => "API key credential added.",
        "credential-generated" => "SSH identity generated.",
        "credential-imported" => "SSH identity imported.",
        "credential-renamed" => "Credential renamed.",
        "credential-rotated" => "API key credential rotated.",
        "credential-revoked" => "Credential revoked.",
        "credential-deleted" => "Credential deleted.",
        "credential-connected" => "Credential connected.",
        "github-app-connected" => "GitHub connected through the GitHub App.",
        "profile-created" => "Credential profile created.",
        "profile-updated" => "Credential profile updated.",
        "profile-deleted" => "Credential profile deleted.",
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "identity-invalid" => "The Git commit identity submission is invalid or too long.",
        "identity-request-failed" => {
            "The Git commit identity change could not be confirmed. Reload before trying again."
        }
        "credential-invalid" => "The credential submission is invalid.",
        "credential-conflict" => "The credential changed. Reload and try again.",
        "credential-in-use" => {
            "The credential is still referenced by a profile and cannot be deleted."
        }
        "credential-uncertain" => {
            "The credential operation may have completed. Reload and inspect it before retrying."
        }
        "credential-request-failed" => "The credential change could not be completed. Try again.",
        "github-app-unavailable" => {
            "GitHub App authorization is not configured yet. No credential was changed. Ask an administrator to finish the GitHub App setup."
        }
        "github-app-cancelled" => {
            "GitHub App authorization was cancelled. No credential was changed."
        }
        "github-app-failed" => {
            "This GitHub connection attempt expired or could not be verified. Continue to GitHub to start a new attempt."
        }
        "github-app-response-invalid" => {
            "Codewire could not verify GitHub's response. Try again; if this continues, ask an administrator to check the GitHub App setup. No credential was changed."
        }
        "github-app-already-connected" => {
            "This GitHub account is already connected. Use its Reconnect action to update repository access."
        }
        "github-installation-required" => {
            "Install the Codewire GitHub App for your account or organization and choose its repositories. Then return here and continue with GitHub. No credential was changed."
        }
        "profile-invalid" => {
            "Check the profile name and selected credentials. Use 1–128 lowercase letters, numbers, hyphens, underscores or dots; start and end with a letter or number."
        }
        "profile-conflict" => "The credential profile changed. Reload and try again.",
        "profile-in-use" => "The credential profile is still in use and cannot be deleted.",
        "request-failed" => "The credential profile change could not be completed. Try again.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{
        CredentialChoicesView, CredentialProfileEntryView, CredentialProfileRowView,
        CredentialRowView, DashboardView,
    };
    use askama::Template as _;

    fn dialog_data() -> credentials_connect::CredentialSettingsData {
        credentials_connect::CredentialSettingsData {
            credentials: vec![CredentialRowView {
                id: "00000000-0000-4000-8000-000000000001".into(),
                name: "legacy-github".into(),
                provider: "GitHub",
                authentication: "OAuth",
                account_hint: "verified-user".into(),
                status: "Active",
                status_tone: "success",
                expires: String::new(),
                generation: 7,
                ssh_public_key: String::new(),
                ssh_fingerprint: String::new(),
                public_key_id: "public-key-1".into(),
                api_key: false,
                oauth: true,
                revoked: false,
                oauth_provider: "github",
            }],
            profiles: vec![CredentialProfileRowView {
                id: "00000000-0000-4000-8000-000000000002".into(),
                name: "work".into(),
                revision: 9,
                entries: vec![CredentialProfileEntryView {
                    slot: "GitHub",
                    credential: "@verified-user".into(),
                    status: "Active",
                    status_tone: "success",
                }],
                codex: String::new(),
                openai: String::new(),
                anthropic: String::new(),
                ssh: String::new(),
            }],
            choices: CredentialChoicesView::default(),
        }
    }

    fn rendered_dialogs(active_dialog: &str, error: &str) -> String {
        rendered_dialogs_with_navigation(active_dialog, error, "?org=sample-org")
    }

    fn rendered_dialogs_with_navigation(
        active_dialog: &str,
        error: &str,
        navigation: &str,
    ) -> String {
        rendered_dialogs_with_data_and_navigation(active_dialog, error, dialog_data(), navigation)
    }

    fn rendered_dialogs_with_data(
        active_dialog: &str,
        error: &str,
        data: credentials_connect::CredentialSettingsData,
    ) -> String {
        rendered_dialogs_with_data_and_navigation(active_dialog, error, data, "?org=sample-org")
    }

    fn rendered_dialogs_with_data_and_navigation(
        active_dialog: &str,
        error: &str,
        data: credentials_connect::CredentialSettingsData,
        navigation: &str,
    ) -> String {
        let view = DashboardView {
            user_name: "Dashboard User".into(),
            csrf_token: Default::default(),
            is_admin: false,
            organizations: Vec::new(),
            has_organizations: false,
            organization_navigation_unavailable: false,
            new_organization_url: "/organizations/new/".into(),
            settings_url: PATH.into(),
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
        };
        let page = CredentialSettingsView {
            navigation_query: navigation.into(),
            creation_return_url: String::new(),
            git_identity: crate::view::SettingsData {
                git_identity_available: true,
                ..Default::default()
            },
            git_identity_feedback: false,
            active_dialog: approved_dialog(active_dialog, &data),
            github_install_url: github_app_installation_url("codewire-synthetic"),
            credentials: data.credentials,
            profiles: data.profiles,
            choices: data.choices,
            csrf_token: "synthetic-csrf".into(),
            message: String::new(),
            error: error.into(),
        };
        CredentialSettingsTemplate {
            view: &view,
            page: &page,
        }
        .render()
        .unwrap()
    }

    #[test]
    fn every_credential_and_profile_form_keeps_page_owned_draft_navigation() {
        let navigation = "?org=sample-org&creation_draft=00000000-0000-4000-8000-000000000003";
        let html = rendered_dialogs_with_navigation("", "", navigation).replace("&#38;", "&amp;");
        let escaped = escape_html(navigation);
        for action in [
            "github/authorize",
            "credentials/oauth/enroll",
            "credentials/api-key/add",
            "credentials/ssh/generate",
            "credentials/ssh/import",
            "profiles/create",
            "profiles/update",
            "profiles/delete",
            "git-identity",
        ] {
            assert!(
                html.contains(&format!("action=\"{PATH}_actions/{action}{escaped}\"")),
                "{action}"
            );
        }
        for form in html.split("<form").skip(1) {
            let opening = form.split('>').next().unwrap();
            if opening.contains(&format!("action=\"{PATH}_actions/")) {
                assert!(
                    opening.contains(&escaped),
                    "credential action lost its draft"
                );
            }
        }
        assert!(!html.contains("/settings/?org=sample-org&amp;creation_draft="));
    }

    #[test]
    fn github_connect_dialog_shows_the_one_connection_instead_of_a_new_authorization() {
        let mut data = dialog_data();
        let mut key = dialog_data().credentials.remove(0);
        key.id = "00000000-0000-4000-8000-000000000004".into();
        key.name = "unrelated-api-key".into();
        key.oauth_provider = "";
        key.oauth = false;
        key.api_key = true;
        data.credentials.push(key);
        let html = rendered_dialogs_with_data("connect-github", "", data);
        let dialog = html
            .split("id=\"connect-github\"")
            .nth(1)
            .unwrap()
            .split("</dialog>")
            .next()
            .unwrap();
        assert!(
            dialog.contains(
                "Your GitHub account <strong>verified-user</strong> is already connected."
            )
        );
        assert!(dialog.contains("disconnect this one and connect again"));
        assert!(dialog.contains("credential-00000000-0000-4000-8000-000000000001-reconnect"));
        assert!(dialog.contains("credential-00000000-0000-4000-8000-000000000001-delete"));
        assert!(!dialog.contains("Your GitHub connection"));
        assert!(!dialog.contains("unrelated-api-key"));
        // A second authorization is never offered while one connection exists.
        assert!(!dialog.contains("Continue to GitHub"));
        assert!(!dialog.contains("connect-github-form"));
    }

    #[test]
    fn github_connect_dialog_without_saved_accounts_does_not_claim_a_connection() {
        let mut data = dialog_data();
        data.credentials.clear();
        data.profiles.clear();
        let html = rendered_dialogs_with_data(
            "connect-github",
            approved_error("github-app-unavailable"),
            data,
        );
        let dialog = html
            .split("id=\"connect-github\"")
            .nth(1)
            .unwrap()
            .split("</dialog>")
            .next()
            .unwrap();
        assert!(!dialog.contains("Saved GitHub connections"));
        assert!(dialog.contains("No credential was changed"));
        assert!(!dialog.contains("may have completed"));
        assert!(dialog.contains("Continue to GitHub"));
    }

    #[test]
    fn dialog_destinations_are_finite_or_present_owned_rows() {
        let data = dialog_data();
        for id in [
            "add-credential",
            "connect-github",
            "connect-codex",
            "add-openai-api-key",
            "add-anthropic-api-key",
            "add-ssh",
            "generate-ssh",
            "import-ssh",
            "create-profile",
            "credential-00000000-0000-4000-8000-000000000001",
            "profile-00000000-0000-4000-8000-000000000002",
            "credential-00000000-0000-4000-8000-000000000001-reconnect",
            "credential-00000000-0000-4000-8000-000000000001-delete",
            "profile-00000000-0000-4000-8000-000000000002-edit",
            "profile-00000000-0000-4000-8000-000000000002-delete",
        ] {
            assert_eq!(approved_dialog(id, &data), id);
        }
        for id in [
            "",
            "#connect-github",
            "dialog[open]",
            "//attacker.example",
            "connect-github\" autofocus",
            "credential-00000000-0000-4000-8000-000000000099",
            "profile-00000000-0000-4000-8000-000000000001",
            "credential-00000000-0000-4000-8000-000000000099-reconnect",
            "credential-00000000-0000-4000-8000-000000000001-edit",
            "credential-00000000-0000-4000-8000-000000000001-rename",
            "credential-00000000-0000-4000-8000-000000000001-rotate",
            // GitHub has no user-visible revoke step; Delete replaces it.
            "credential-00000000-0000-4000-8000-000000000001-revoke",
            "profile-00000000-0000-4000-8000-000000000002-reconnect",
            "profile-00000000-0000-4000-8000-000000000002-edit-delete",
            "add-api-key",
        ] {
            assert!(approved_dialog(id, &data).is_empty(), "{id}");
        }
        assert!(row_dialog("unknown", &data.credentials[0].id).is_empty());
        assert!(row_dialog("credential", "<private-marker>").is_empty());
    }

    #[test]
    fn list_first_dialogs_preserve_profile_and_credential_fences() {
        let html = rendered_dialogs("", "");
        assert!(!html.contains("Credential inventory"));
        assert!(
            html.find("id=\"credentials-title\"").unwrap()
                < html.find("id=\"add-credential\"").unwrap()
        );
        assert!(
            html.find("id=\"profiles-title\"").unwrap()
                < html.find("id=\"create-profile\"").unwrap()
        );
        assert_eq!(html.matches("data-dialog id=").count(), 15);
        assert!(!html.contains("data-dialog-auto-open"));
        assert!(!html.contains("<dialog open"));
        assert!(html.contains("name=\"expected_revocation_generation\" value=\"7\""));
        assert!(html.contains("name=\"expected_revision\" value=\"9\""));
        let credential_row = html.split("class=\"cw-credential-row\"").nth(1).unwrap();
        let (credential_primary, credential_dialog) = credential_row.split_once("<dialog").unwrap();
        assert!(!credential_primary.contains("Generation"));
        assert!(!credential_primary.contains("Expires"));
        assert!(credential_primary.contains("Active"));
        // The GitHub connection dialog carries no Details or Generation copy.
        assert!(
            !credential_dialog
                .split("</dialog>")
                .next()
                .unwrap()
                .contains("Generation")
        );
        let profile_row = html.split("class=\"cw-profile-row\"").nth(1).unwrap();
        let (profile_primary, profile_dialog) = profile_row.split_once("<dialog").unwrap();
        assert!(!profile_primary.contains("Revision"));
        assert!(
            profile_dialog
                .split("</dialog>")
                .next()
                .unwrap()
                .contains("Revision 9")
        );
        assert!(!html.contains("name=\"name\" value=\"legacy-github\""));
        assert!(html.contains("name=\"confirm_reconnect\" value=\"yes\" required"));
        assert!(
            html.contains("Editing a profile")
                || html.contains("existing Sandboxes keep their bound revision")
        );
        assert!(html.contains("/settings/credentials/_actions/profiles/update?org=sample-org"));
        assert!(html.contains("name=\"private_key\" data-dialog-private"));
        assert!(html.contains("type=\"password\" data-dialog-private"));
        for form in html.split("<form").skip(1) {
            let opening = form.split('>').next().unwrap();
            if opening.contains("cw-settings-form") {
                assert_eq!(
                    opening.contains("data-dirty-guard"),
                    !opening.contains("_actions/git-identity")
                        && !opening.contains("/delete")
                        && !opening.contains("/revoke"),
                    "only editable credential/profile dialogs opt into close protection"
                );
            }
            if form
                .split("</form>")
                .next()
                .unwrap()
                .contains("name=\"confirm_reconnect\"")
            {
                assert!(opening.contains("data-dirty-guard"));
            }
        }
        let github = html
            .split("aria-labelledby=\"connect-github-title\"")
            .nth(1)
            .unwrap()
            .split("</dialog>")
            .next()
            .unwrap();
        assert!(!github.contains("name=\"name\""));
        assert!(!github.contains("name=\"provider\""));
        // The fixture account already has its one GitHub connection, so the
        // connect dialog routes to Reconnect instead of a second authorization.
        assert!(github.contains("is already connected"));
        assert!(!github.contains("Continue to GitHub"));
        assert!(!github.contains("one-time code"));
        // Reconnect keeps the verified-account authorization and install link.
        assert!(html.contains("/settings/credentials/_actions/github/authorize?org=sample-org"));
        assert!(html.contains("https://github.com/apps/codewire-synthetic/installations/new"));
        assert!(html.contains("icons-v2.svg#icon-github"));
    }

    #[test]
    fn validation_reopens_only_the_relevant_dialog_with_escaped_static_error() {
        let html = rendered_dialogs("add-openai-api-key", approved_error("credential-invalid"));
        assert_eq!(html.matches("data-dialog-auto-open").count(), 1);
        assert_eq!(html.matches("role=\"alert\"").count(), 1);
        assert!(html.contains(
            "id=\"add-openai-api-key\" aria-labelledby=\"add-openai-api-key-title\" data-dialog-auto-open"
        ));
        assert!(html.contains("The credential submission is invalid."));
        assert!(!html.contains("name=\"value\" value="));
        let html = rendered_dialogs(
            "profile-00000000-0000-4000-8000-000000000002-edit",
            "<unsafe>",
        );
        assert_eq!(html.matches("data-dialog-auto-open").count(), 1);
        assert!(!html.contains("<unsafe>"));
        assert!(html.contains("&lt;unsafe&gt;") || html.contains("&#60;unsafe&#62;"));
    }

    #[test]
    fn dialog_error_redirect_carries_only_static_error_and_context() {
        let response = page_error_redirect(
            "credential-invalid",
            "add-openai-api-key",
            &QueryParameters {
                org: "sample-org".into(),
                ..Default::default()
            },
            &HeaderMap::new(),
        );
        assert_eq!(
            response.headers()[header::LOCATION],
            "/settings/credentials/?error=credential-invalid&dialog=add-openai-api-key"
        );
        let response = credential_mutation_error(
            ErrorCode::Unavailable,
            false,
            "add-openai-api-key",
            &QueryParameters::default(),
            &HeaderMap::new(),
        );
        assert_eq!(
            response.headers()[header::LOCATION],
            "/settings/credentials/?error=credential-uncertain&dialog=add-openai-api-key"
        );
    }

    #[test]
    fn profile_names_match_the_shared_identifier_contract() {
        for name in [
            "a",
            "1",
            "github-repository-browser",
            "work_1.v2",
            &"a".repeat(128),
        ] {
            assert!(valid_name(name), "valid profile name: {name}");
        }
        for name in [
            "",
            "GitHub repository browser",
            "Work",
            "work profile",
            "-work",
            "work.",
            "wörk",
            &"a".repeat(129),
        ] {
            assert!(!valid_name(name), "invalid profile name: {name}");
        }
        assert!(valid_credential_name("Work API"));
    }

    #[test]
    fn entries_are_closed_and_use_exact_credential_ids() {
        let id = "00000000-0000-4000-8000-000000000001";
        let profile_entries =
            entries(id.into(), String::new(), String::new(), String::new()).unwrap();
        assert_eq!(profile_entries.len(), 1);
        assert_eq!(profile_entries[0].capability_slot, "codex");
        assert_eq!(profile_entries[0].credential_id, id);
        assert!(
            entries(
                "not-an-id".into(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn github_browser_authorization_is_an_app_redirect_not_device_enrollment() {
        let submission: GitHubAppAuthorizationSubmission =
            serde_json::from_value(serde_json::json!({"_csrf": "synthetic-csrf"})).unwrap();
        assert!(submission.credential_id.is_empty());
        assert!(submission.expected_revocation_generation.is_none());
        assert!(web_device_oauth_provider("codex").is_some());
        assert!(web_device_oauth_provider("github").is_none());
        assert!(valid_oauth_name("Codex work"));
        assert!(!valid_oauth_name(""));

        let installation = github_app_installation_url("codewire");
        let url = Url::parse(&installation).unwrap();
        assert_eq!(
            url.as_str(),
            "https://github.com/apps/codewire/installations/new"
        );
        assert!(!installation.contains("device"));
        assert!(!installation.contains("redirect_uri"));
        assert!(github_app_installation_url("").is_empty());
        for origin in [
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8090",
            "https://codewire-dev.sh",
        ] {
            let authorization = Url::parse(&github_app_authorization_url(
                "Iv1.syntheticclient",
                origin,
                "opaque-state",
            ))
            .unwrap();
            assert_eq!(
                authorization.origin().ascii_serialization(),
                "https://github.com"
            );
            assert_eq!(authorization.path(), "/login/oauth/authorize");
            let parameters: std::collections::BTreeMap<_, _> =
                authorization.query_pairs().collect();
            assert_eq!(parameters.len(), 3);
            assert_eq!(parameters["client_id"], "Iv1.syntheticclient");
            assert_eq!(parameters["state"], "opaque-state");
            assert_eq!(
                parameters["redirect_uri"],
                format!("{origin}/api/v1/github/oauth/callback")
            );
            assert!(!authorization.as_str().contains("device"));
        }
        assert!(valid_github_app_callback_code("a-b_c.d~9"));
        assert!(!valid_github_app_callback_code("invalid?code"));
    }

    #[test]
    fn github_callback_response_drops_authorization_code_referrers_and_cache_entries() {
        let response = github_app_callback_response(
            Response::new(Body::empty()),
            "codewire_github_app_authorization=deleted".into(),
        );
        assert_eq!(
            response.headers()[header::REFERRER_POLICY],
            HeaderValue::from_static("no-referrer")
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            HeaderValue::from_static("no-store, max-age=0")
        );
    }

    #[test]
    fn github_callback_query_rejects_duplicate_security_fields() {
        for query in [
            "code=first&code=second&state=state",
            "code=code&state=first&state=second",
            "code=code&state=state&error=first&error=second",
        ] {
            let uri = format!("{GITHUB_APP_CALLBACK_PATH}?{query}")
                .parse()
                .unwrap();
            assert!(Query::<GitHubAppCallbackQuery>::try_from_uri(&uri).is_err());
        }
        let uri = format!("{GITHUB_APP_CALLBACK_PATH}?code=code&state=state")
            .parse()
            .unwrap();
        assert!(Query::<GitHubAppCallbackQuery>::try_from_uri(&uri).is_ok());
    }

    #[test]
    fn enrollment_errors_explain_recovery_and_uncertain_publication_separately() {
        use credentials_connect::{
            OAuthEnrollmentEvent as Event, OAuthEnrollmentFailure as Failure,
        };
        let duplicate = render_enrollment_event(
            Event::Failed {
                reason: Failure::AlreadyExists,
                uncertain: false,
            },
            "/settings/credentials/",
        );
        assert!(duplicate.contains("No credential was overwritten"));
        assert!(!duplicate.contains("may already be saved"));
        let uncertain = render_enrollment_event(
            Event::Failed {
                reason: Failure::Unavailable,
                uncertain: true,
            },
            "/settings/credentials/",
        );
        assert!(uncertain.contains("busy or unavailable"));
        assert!(uncertain.contains("may already be saved"));
        let unsupported = render_enrollment_event(
            Event::Failed {
                reason: Failure::Unsupported,
                uncertain: false,
            },
            "/settings/credentials/",
        );
        assert!(unsupported.contains("could not verify the provider's response"));
    }

    #[test]
    fn enrollment_events_carry_only_the_challenge_and_outcome() {
        use credentials_connect::{
            OAuthEnrollmentEvent as Event, OAuthEnrollmentFailure as Failure,
        };
        let frame = |event| {
            enrollment_event_frame(event, "/settings/credentials/?message=credential-connected")
        };
        let challenge = frame(Event::Challenge {
            provider: "OpenAI Codex",
            verification_url: "https://auth.openai.com/codex/device".into(),
            user_code: "ABCD-1234".into(),
            expires_utc: "2026-09-29 14:01 UTC".into(),
        });
        assert!(challenge.starts_with("event: challenge\ndata: {"));
        assert!(challenge.ends_with("}\n\n"));
        let data: serde_json::Value = serde_json::from_str(
            challenge
                .lines()
                .nth(1)
                .unwrap()
                .strip_prefix("data: ")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["userCode"], "ABCD-1234");
        assert_eq!(
            data["verificationUrl"],
            "https://auth.openai.com/codex/device"
        );
        assert_eq!(
            frame(Event::Committed),
            "event: connected\ndata: {\"location\":\"/settings/credentials/?message=credential-connected\"}\n\n"
        );
        let failed = frame(Event::Failed {
            reason: Failure::Expired,
            uncertain: true,
        });
        assert!(failed.starts_with("event: failed\n"));
        assert!(failed.contains("\"uncertain\":true"));
        assert!(failed.contains("expired before it was approved"));
        let mut headers = HeaderMap::new();
        assert!(!wants_enrollment_events(&headers));
        headers.insert(header::ACCEPT, "text/event-stream".parse().unwrap());
        assert!(wants_enrollment_events(&headers));
        assert_eq!(
            approved_message("credential-connected"),
            "Credential connected."
        );
    }

    #[test]
    fn redirects_preserve_only_static_messages() {
        assert_eq!(
            approved_message("profile-created"),
            "Credential profile created."
        );
        assert!(approved_message("attacker text").is_empty());
        assert!(approved_error("attacker text").is_empty());
        assert_eq!(
            mutation_error_code(ErrorCode::InvalidArgument, false),
            "profile-invalid"
        );
        assert!(approved_error("profile-invalid").contains("selected credentials"));
        assert_eq!(
            mutation_error_code(ErrorCode::FailedPrecondition, false),
            "request-failed"
        );
        assert_eq!(
            mutation_error_code(ErrorCode::FailedPrecondition, true),
            "profile-in-use"
        );
        assert_eq!(
            approved_error("credential-uncertain"),
            "The credential operation may have completed. Reload and inspect it before retrying."
        );
        assert_eq!(
            approved_error("github-app-already-connected"),
            "This GitHub account is already connected. Use its Reconnect action to update repository access."
        );
    }

    #[test]
    fn expiry_is_explicit_utc_and_html_fragments_escape_values() {
        assert!(parse_expiration_utc("").unwrap().is_none());
        assert!(parse_expiration_utc("not-a-date").is_err());
        assert!(parse_expiration_utc("2000-01-01T00:00").is_err());
        assert!(parse_expiration_utc("2100-01-01T00:00").unwrap().is_some());
        assert_eq!(escape_html("<&\"'>"), "&lt;&amp;&quot;&#39;&gt;");
        let fragment = render_enrollment_event(
            credentials_connect::OAuthEnrollmentEvent::Challenge {
                provider: "Provider",
                verification_url: "https://example.test/?x=<unsafe>".into(),
                user_code: "<unsafe>".into(),
                expires_utc: "2100-01-01 00:00 UTC".into(),
            },
            "/settings/credentials/",
        );
        assert!(!fragment.contains("<unsafe>"));
        assert!(fragment.contains("&lt;unsafe&gt;"));
    }

    #[tokio::test]
    async fn draft_navigation_is_independent_of_existing_query_authority() {
        use axum::http::Request;
        const DRAFT: &str = "00000000-0000-4000-8000-000000000003";
        for (raw, exact) in [
            (format!("creation_draft={DRAFT}"), true),
            (format!("%63reation_draft={DRAFT}"), true),
            (
                format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
                false,
            ),
            (
                format!("creation_draft={DRAFT}&%63reation_draft={DRAFT}"),
                false,
            ),
            ("creation_draft=https%3A%2F%2Fforeign.invalid".into(), false),
            (
                "creation_draft=00000000-0000-0000-0000-000000000000".into(),
                false,
            ),
            (
                format!("creation_draft={DRAFT}&value={}", "x".repeat(1024)),
                false,
            ),
            (String::new(), false),
        ] {
            let request = Request::builder()
                .uri(format!(
                    "{PATH}?org=synthetic&{raw}&message=profile-created&dialog=create-profile"
                ))
                .body(())
                .unwrap();
            let (mut parts, _) = request.into_parts();
            let CredentialQuery(context) = CredentialQuery::from_request_parts(&mut parts, &())
                .await
                .unwrap();
            assert_eq!(context.org, "synthetic");
            assert_eq!(context.message, "profile-created");
            assert_eq!(context.dialog, "create-profile");
            assert_eq!(matches!(context.draft, DraftReturn::Exact(_)), exact);
            let target =
                page_feedback_target(&context, "error", "credential-invalid", "add-api-key");
            assert_eq!(target.contains("creation_draft="), exact);
            assert_eq!(target.matches('?').count(), 1);
            assert!(!target.contains("foreign.invalid") && !target.contains("value="));
        }
        // Keep the ordinary query extractor's duplicate-organization
        // rejection; only draft navigation parsing changes here.
        for raw in ["org=one&org=two", "org=one&org=two&creation_draft=bad"] {
            let request = Request::builder()
                .uri(format!("{PATH}?{raw}"))
                .body(())
                .unwrap();
            let (mut original, _) = request.into_parts();
            let mut current = original.clone();
            assert!(
                Query::<QueryParameters>::from_request_parts(&mut original, &())
                    .await
                    .is_err()
            );
            assert!(
                CredentialQuery::from_request_parts(&mut current, &())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn enrollment_completion_and_failure_keep_only_closed_draft_navigation() {
        const DRAFT: &str = "00000000-0000-4000-8000-000000000003";
        let context = QueryParameters {
            org: "synthetic".into(),
            draft: DraftReturn::Exact(DRAFT.into()),
            ..Default::default()
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        drop(sender);
        let response = enrollment_response(receiver, &context);
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        for event in [
            credentials_connect::OAuthEnrollmentEvent::Committed,
            credentials_connect::OAuthEnrollmentEvent::Failed {
                reason: credentials_connect::OAuthEnrollmentFailure::Cancelled,
                uncertain: false,
            },
        ] {
            let html = render_enrollment_event(event, &escape_html(&page_path(&context)));
            assert!(html.contains(&format!(
                "href=\"/settings/credentials/?creation_draft={DRAFT}\""
            )));
            assert!(!html.contains("synthetic-session"));
        }
    }

    #[tokio::test]
    async fn dropping_enrollment_response_closes_the_owned_event_stream() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let response = enrollment_response(receiver, &QueryParameters::default());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, no-cache, must-revalidate"
        );
        assert_eq!(response.headers().get("x-accel-buffering").unwrap(), "no");
        drop(response);
        tokio::time::timeout(std::time::Duration::from_secs(1), sender.closed())
            .await
            .expect("response-body drop closes enrollment receiver");
    }
}
