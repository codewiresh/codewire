use std::convert::Infallible;

use axum::{
    Form,
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use chrono::{NaiveDateTime, Utc};
use codewire_proto::codewire::v1::AccessProfileEntry;
use connectrpc::ErrorCode;
use serde::Deserialize;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};

use crate::{
    credentials_connect,
    environment_source_forms::exact_id,
    error::WebError,
    response::{error_page, login_redirect, redirect, render_page, two_factor_redirect},
    security::{canonical_cookie, csrf_cookie, new_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::CredentialSettingsTemplate,
    view::{
        CredentialApiKeySubmission, CredentialOAuthSubmission, CredentialProfileCreateSubmission,
        CredentialProfileDeleteSubmission, CredentialProfileUpdateSubmission,
        CredentialRenameSubmission, CredentialRevisionSubmission, CredentialRotateSubmission,
        CredentialSettingsView, CredentialSshGenerateSubmission, CredentialSshImportSubmission,
    },
};

const PATH: &str = "/settings/credentials/";

#[derive(Debug, Default, Deserialize)]
pub(super) struct QueryParameters {
    #[serde(default)]
    org: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<QueryParameters>,
) -> Response {
    let continuation = page_path(&query.org);
    let mut dashboard = match super::dashboard::dashboard_shell_view(&state, &headers).await {
        Ok(view) => view,
        Err(WebError::Unauthorized) => return login_redirect(&continuation, &headers),
        Err(WebError::TwoFactorRequired) => return two_factor_redirect(&continuation, &headers),
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
    let data = match credentials_connect::settings_data(&state, cookie).await {
        Ok(data) => data,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&continuation, &headers);
        }
        Err(error) => return error_page(WebError::Connect(error)),
    };
    let csrf = new_csrf_token();
    let page = CredentialSettingsView {
        credentials: data.credentials,
        profiles: data.profiles,
        choices: data.choices,
        csrf_token: csrf.clone(),
        message: approved_message(&query.message).into(),
        error: approved_error(&query.error).into(),
    };
    with_csrf_cookie(
        render_page(CredentialSettingsTemplate {
            view: &dashboard,
            page: &page,
        }),
        csrf_cookie(&state.public_origin, &csrf),
    )
}

pub(super) async fn create_profile_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileCreateSubmission>,
) -> Response {
    let cookie = match super::settings::mutation_cookie(
        &state, &headers, &form.csrf, &query.org, PATH,
    )
    .await
    {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    if !valid_name(name) {
        return page_redirect("profile-invalid", true, &query.org, &headers);
    }
    let entries = match entries(
        form.codex,
        form.openai,
        form.github,
        form.anthropic,
        form.ssh,
    ) {
        Ok(entries) => entries,
        Err(()) => return page_redirect("profile-invalid", true, &query.org, &headers),
    };
    match credentials_connect::create_profile(&state, cookie, name.into(), entries).await {
        Ok(()) => page_redirect("profile-created", false, &query.org, &headers),
        Err(error) => mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn update_profile_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileUpdateSubmission>,
) -> Response {
    let cookie = match super::settings::mutation_cookie(
        &state, &headers, &form.csrf, &query.org, PATH,
    )
    .await
    {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.profile_id).is_err() || !valid_revision(form.expected_revision) {
        return page_redirect("profile-invalid", true, &query.org, &headers);
    }
    let entries = match entries(
        form.codex,
        form.openai,
        form.github,
        form.anthropic,
        form.ssh,
    ) {
        Ok(entries) => entries,
        Err(()) => return page_redirect("profile-invalid", true, &query.org, &headers),
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
        Ok(()) => page_redirect("profile-updated", false, &query.org, &headers),
        Err(error) => mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn delete_profile_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileDeleteSubmission>,
) -> Response {
    let cookie = match super::settings::mutation_cookie(
        &state, &headers, &form.csrf, &query.org, PATH,
    )
    .await
    {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.profile_id).is_err() || !valid_revision(form.expected_revision) {
        return page_redirect("profile-invalid", true, &query.org, &headers);
    }
    match credentials_connect::delete_profile(
        &state,
        cookie,
        form.profile_id,
        form.expected_revision,
    )
    .await
    {
        Ok(()) => page_redirect("profile-deleted", false, &query.org, &headers),
        Err(error) => mutation_error(error.code, true, &query.org, &headers),
    }
}

pub(super) async fn add_api_key_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialApiKeySubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
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
        return page_redirect("credential-invalid", true, &query.org, &headers);
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
        Ok(()) => page_redirect("credential-added", false, &query.org, &headers),
        Err(error) => credential_mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn generate_ssh_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialSshGenerateSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let expiry = parse_expiration_utc(&form.expiration_utc);
    if !valid_credential_name(name) || expiry.is_err() {
        return page_redirect("credential-invalid", true, &query.org, &headers);
    }
    match credentials_connect::generate_ssh(
        &state,
        cookie,
        name.into(),
        expiry.expect("checked above"),
    )
    .await
    {
        Ok(()) => page_redirect("credential-generated", false, &query.org, &headers),
        Err(error) => credential_mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn import_ssh_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialSshImportSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
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
        return page_redirect("credential-invalid", true, &query.org, &headers);
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
        Ok(()) => page_redirect("credential-imported", false, &query.org, &headers),
        Err(error) => credential_mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn rename_credential_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialRenameSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    if exact_id(&form.credential_id).is_err()
        || !valid_generation(form.expected_revocation_generation, false)
        || !valid_credential_name(&form.expected_name)
        || !valid_credential_name(name)
    {
        return page_redirect("credential-invalid", true, &query.org, &headers);
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
        Ok(()) => page_redirect("credential-renamed", false, &query.org, &headers),
        Err(error) => credential_mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn rotate_api_key_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialRotateSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
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
        return page_redirect("credential-invalid", true, &query.org, &headers);
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
        Ok(()) => page_redirect("credential-rotated", false, &query.org, &headers),
        Err(error) => credential_mutation_error(error.code, false, &query.org, &headers),
    }
}

pub(super) async fn revoke_credential_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialRevisionSubmission>,
) -> Response {
    credential_revision_action(state, query, headers, form, false).await
}

pub(super) async fn delete_credential_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialRevisionSubmission>,
) -> Response {
    credential_revision_action(state, query, headers, form, true).await
}

pub(super) async fn enroll_oauth_action(
    State(state): State<AppState>,
    Query(query): Query<QueryParameters>,
    headers: HeaderMap,
    Form(form): Form<CredentialOAuthSubmission>,
) -> Response {
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let provider = match form.provider.as_str() {
        "codex" => credentials_connect::OAuthProvider::Codex,
        "github" => credentials_connect::OAuthProvider::Github,
        _ => return page_redirect("credential-invalid", true, &query.org, &headers),
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
        _ => return page_redirect("credential-invalid", true, &query.org, &headers),
    };
    if !valid_credential_name(name) {
        return page_redirect("credential-invalid", true, &query.org, &headers);
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
    enrollment_response(receiver, &query.org)
}

fn enrollment_response(
    receiver: tokio::sync::mpsc::Receiver<credentials_connect::OAuthEnrollmentEvent>,
    org: &str,
) -> Response {
    let prefix = concat!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>Connect credential · Codewire</title>",
        "<link rel=\"stylesheet\" href=\"/assets/codewire/design-v1.css\">",
        "</head><body class=\"cw-body\"><main class=\"cw-main\"><div class=\"cw-main-inner\">",
        "<section class=\"cw-card\" aria-labelledby=\"credential-enrollment-title\">",
        "<div class=\"cw-card-header\"><h1 id=\"credential-enrollment-title\" class=\"cw-card-title\">Connect credential</h1>",
        "<p class=\"cw-card-description\">Keep this page open until Codewire confirms the credential.</p></div>",
        "<div class=\"cw-card-content\">"
    );
    let return_path = escape_html(&page_path(org));
    let stream = tokio_stream::iter([Ok::<Bytes, Infallible>(Bytes::from_static(
        prefix.as_bytes(),
    ))])
    .chain(
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
    match event {
        credentials_connect::OAuthEnrollmentEvent::Challenge {
            provider,
            verification_url,
            user_code,
            expires_utc,
        } => format!(
            "<section aria-labelledby=\"credential-challenge-title\"><h2 id=\"credential-challenge-title\">Authorize {}</h2><p><a class=\"cw-button\" href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">Open {} authorization</a></p><p>Enter this one-time code:</p><p><code>{}</code></p><p>Codewire is waiting for the provider. This challenge expires at {}.</p></section>",
            escape_html(provider),
            escape_html(&verification_url),
            escape_html(provider),
            escape_html(&user_code),
            escape_html(&expires_utc),
        ),
        credentials_connect::OAuthEnrollmentEvent::Committed => format!(
            "<div class=\"cw-alert cw-alert--success\" role=\"status\">Credential connected.</div><p><a class=\"cw-button\" href=\"{return_path}\">Return to credentials</a></p></div></section></div></main></body></html>"
        ),
        credentials_connect::OAuthEnrollmentEvent::Failed { uncertain } => {
            let message = if uncertain {
                "The final acknowledgement was not received. Return to credentials and inspect the named credential before retrying."
            } else {
                "The credential could not be connected. Return to credentials and try again."
            };
            format!(
                "<div class=\"cw-alert cw-alert--error\" role=\"alert\">{message}</div><p><a class=\"cw-button\" href=\"{return_path}\">Return to credentials</a></p></div></section></div></main></body></html>"
            )
        }
    }
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
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query.org).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.credential_id).is_err()
        || !valid_generation(form.expected_revocation_generation, !delete)
    {
        return page_redirect("credential-invalid", true, &query.org, &headers);
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
            &query.org,
            &headers,
        ),
        Err(error) => credential_mutation_error(error.code, delete, &query.org, &headers),
    }
}

async fn mutation_cookie(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    org: &str,
) -> Result<axum::http::HeaderValue, Response> {
    super::settings::mutation_cookie(state, headers, csrf, org, PATH).await
}

fn entries(
    codex: String,
    openai: String,
    github: String,
    anthropic: String,
    ssh: String,
) -> Result<Vec<AccessProfileEntry>, ()> {
    let mut entries = Vec::new();
    for (slot, credential_id) in [
        ("codex", codex),
        ("openai", openai),
        ("github", github),
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
    !name.is_empty() && name.len() <= 128 && !name.bytes().any(|byte| byte.is_ascii_control())
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

fn mutation_error(code: ErrorCode, delete: bool, org: &str, headers: &HeaderMap) -> Response {
    if code == ErrorCode::Unauthenticated {
        return login_redirect(&page_path(org), headers);
    }
    page_redirect(mutation_error_code(code, delete), true, org, headers)
}

fn credential_mutation_error(
    code: ErrorCode,
    delete: bool,
    org: &str,
    headers: &HeaderMap,
) -> Response {
    if code == ErrorCode::Unauthenticated {
        return login_redirect(&page_path(org), headers);
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
    page_redirect(error, true, org, headers)
}

fn mutation_error_code(code: ErrorCode, delete: bool) -> &'static str {
    if code == ErrorCode::Aborted || code == ErrorCode::AlreadyExists {
        "profile-conflict"
    } else if delete && code == ErrorCode::FailedPrecondition {
        "profile-in-use"
    } else {
        "request-failed"
    }
}

fn page_path(org: &str) -> String {
    if org.is_empty() {
        PATH.into()
    } else {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("org", org);
        format!("{PATH}?{}", query.finish())
    }
}

fn page_redirect(code: &str, error: bool, org: &str, headers: &HeaderMap) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if !org.is_empty() {
        query.append_pair("org", org);
    }
    query.append_pair(if error { "error" } else { "message" }, code);
    redirect(format!("{PATH}?{}", query.finish()), headers)
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "credential-added" => "API key credential added.",
        "credential-generated" => "SSH identity generated.",
        "credential-imported" => "SSH identity imported.",
        "credential-renamed" => "Credential renamed.",
        "credential-rotated" => "API key credential rotated.",
        "credential-revoked" => "Credential revoked.",
        "credential-deleted" => "Credential deleted.",
        "profile-created" => "Credential profile created.",
        "profile-updated" => "Credential profile updated.",
        "profile-deleted" => "Credential profile deleted.",
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "credential-invalid" => "The credential submission is invalid.",
        "credential-conflict" => "The credential changed. Reload and try again.",
        "credential-in-use" => {
            "The credential is still referenced by a profile and cannot be deleted."
        }
        "credential-uncertain" => {
            "The credential operation may have completed. Reload and inspect it before retrying."
        }
        "credential-request-failed" => "The credential change could not be completed. Try again.",
        "profile-invalid" => "The credential profile is invalid.",
        "profile-conflict" => "The credential profile changed. Reload and try again.",
        "profile-in-use" => "The credential profile is still in use and cannot be deleted.",
        "request-failed" => "The credential profile change could not be completed. Try again.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_closed_and_use_exact_credential_ids() {
        let id = "00000000-0000-4000-8000-000000000001";
        let profile_entries = entries(
            id.into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .unwrap();
        assert_eq!(profile_entries.len(), 1);
        assert_eq!(profile_entries[0].capability_slot, "codex");
        assert_eq!(profile_entries[0].credential_id, id);
        assert!(
            entries(
                "not-an-id".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new()
            )
            .is_err()
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
    async fn dropping_enrollment_response_closes_the_owned_event_stream() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let response = enrollment_response(receiver, "");
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
