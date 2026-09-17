use axum::{
    Form,
    extract::{
        Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRET_KEY_BYTES, MAX_WORKLOAD_SECRET_VALUE_BYTES, validate_workload_secret_key,
    validate_workload_secret_value,
};
use connectrpc::ErrorCode;
use serde::Deserialize;

use crate::{
    account_sessions,
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    error::WebError,
    response::{error_page, login_redirect, redirect, render_template, two_factor_redirect},
    secrets_presets_connect::{self, SecretBucket},
    security::{canonical_cookie, csrf_cookie, new_csrf_token, valid_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::SettingsSecretsTemplate,
    view::{PersonalSecretsPageView, SecretFormView},
};

pub(super) const PATH: &str = "/settings/secrets/";

#[derive(Default, Deserialize)]
pub(super) struct PageQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

// These forms hold request authority and, for SetForm, write-only material.
// They must not derive Debug or be placed into retained rendering state.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetForm {
    #[serde(rename = "_csrf")]
    pub(super) csrf: String,
    #[serde(default)]
    pub(super) account_id: String,
    pub(super) key: String,
    pub(super) value: String,
    #[serde(default)]
    pub(super) mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenameForm {
    #[serde(rename = "_csrf")]
    pub(super) csrf: String,
    #[serde(default)]
    pub(super) account_id: String,
    pub(super) key: String,
    pub(super) new_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteForm {
    #[serde(rename = "_csrf")]
    pub(super) csrf: String,
    #[serde(default)]
    pub(super) account_id: String,
    pub(super) key: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return feedback(&headers, &PageQuery::default(), "error", "invalid-page");
    };
    let (identity, cookie) = match identity_context(&state, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    render(
        &state,
        &headers,
        &identity,
        cookie,
        &query,
        PersonalSecretsPageView::default(),
        StatusCode::OK,
    )
    .await
}

pub(super) async fn legacy_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // The obsolete organization prefix cannot gate or broaden personal access.
    if let Err(response) = identity_context(&state, &headers).await {
        return response;
    }
    private(redirect(PATH.to_owned(), &headers))
}

async fn identity_context(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(IdentityUser, HeaderValue), Response> {
    if !account_sessions::cookie_authority_is_unique(headers) {
        return Err(private(login_redirect(PATH, headers)));
    }
    let cookie = canonical_cookie(headers).map_err(|()| private(login_redirect(PATH, headers)))?;
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| identity_error(error, headers))?;
    enforce_two_factor(&identity).map_err(|_| private(two_factor_redirect(PATH, headers)))?;
    Ok((identity, cookie))
}

fn identity_error(error: WebError, headers: &HeaderMap) -> Response {
    private(match error {
        WebError::Unauthorized => login_redirect(PATH, headers),
        WebError::TwoFactorRequired => two_factor_redirect(PATH, headers),
        error => error_page(error),
    })
}

async fn mutation_context(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    account_id: &str,
) -> Result<(IdentityUser, HeaderValue), Response> {
    if !account_sessions::mutation_origin_is_exact(headers, &state.public_origin)
        || !valid_csrf_token(headers, csrf)
    {
        return Err(private(error_page(WebError::CsrfRejected)));
    }
    let (identity, cookie) = identity_context(state, headers).await?;
    if !account_sessions::valid_id(account_id) || identity.id != account_id {
        return Err(feedback(
            headers,
            &PageQuery::default(),
            "error",
            "account-changed",
        ));
    }
    // No organization lookup. The submitted ID detects a stale account, but
    // only this exact authenticated session authorizes the owning User RPC.
    Ok((identity, cookie))
}

pub(super) async fn set_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
    form: Result<Form<SetForm>, FormRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return private(error_page(WebError::Forbidden));
    };
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (identity, cookie) =
        match mutation_context(&state, &headers, &form.csrf, &form.account_id).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let mut page = PersonalSecretsPageView {
        form: SecretFormView {
            key: form.key.trim().to_owned(),
            ..Default::default()
        },
        active_dialog: if form.mode == "replace" {
            "value"
        } else {
            "add-secret"
        }
        .into(),
        ..Default::default()
    };
    validate_key(&mut page.form);
    if validate_workload_secret_value(form.value.as_bytes()).is_err() {
        page.form.form_error = format!(
            "Enter a nonempty UTF-8 value of at most {MAX_WORKLOAD_SECRET_VALUE_BYTES} bytes, without NUL characters. Values are never shown again."
        );
    }
    if !matches!(form.mode.as_str(), "add" | "replace") {
        page.form.form_error = "Reload Secrets before trying again.".into();
    }
    if page.form.key_error.is_empty() && page.form.form_error.is_empty() {
        let result = secrets_presets_connect::set_secret(
            &state,
            cookie.clone(),
            String::new(),
            SecretBucket::User,
            page.form.key.clone(),
            form.value,
        )
        .await;
        match result {
            Ok(()) => return feedback(&headers, &query, "message", "secret-saved"),
            Err(error) if error.code == ErrorCode::Unauthenticated => {
                return private(login_redirect(PATH, &headers));
            }
            Err(error) => page.form.form_error = mutation_error(error.code).into(),
        }
    }
    render(
        &state,
        &headers,
        &identity,
        cookie,
        &query,
        page,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await
}

pub(super) async fn rename_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
    form: Result<Form<RenameForm>, FormRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return private(error_page(WebError::Forbidden));
    };
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (identity, cookie) =
        match mutation_context(&state, &headers, &form.csrf, &form.account_id).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let mut page = PersonalSecretsPageView {
        form: SecretFormView {
            key: form.key,
            ..Default::default()
        },
        new_key: form.new_key.trim().to_owned(),
        active_dialog: "rename".into(),
        ..Default::default()
    };
    if validate_workload_secret_key(&page.form.key).is_err()
        || validate_workload_secret_key(&page.new_key).is_err()
        || page.form.key == page.new_key
    {
        page.form.form_error = format!(
            "Choose a different key using 1–{MAX_WORKLOAD_SECRET_KEY_BYTES} ASCII letters, numbers or underscores, starting with a letter or underscore."
        );
    } else {
        match secrets_presets_connect::rename_secret(
            &state,
            cookie.clone(),
            String::new(),
            SecretBucket::User,
            page.form.key.clone(),
            page.new_key.clone(),
        )
        .await
        {
            Ok(()) => return feedback(&headers, &query, "message", "secret-renamed"),
            Err(error) if error.code == ErrorCode::Unauthenticated => {
                return private(login_redirect(PATH, &headers));
            }
            Err(error) => page.form.form_error = mutation_error(error.code).into(),
        }
    }
    render(
        &state,
        &headers,
        &identity,
        cookie,
        &query,
        page,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await
}

pub(super) async fn delete_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
    form: Result<Form<DeleteForm>, FormRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return private(error_page(WebError::Forbidden));
    };
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (_, cookie) = match mutation_context(&state, &headers, &form.csrf, &form.account_id).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if validate_workload_secret_key(&form.key).is_err() {
        return feedback(&headers, &query, "error", "invalid-key");
    }
    match secrets_presets_connect::delete_secret(
        &state,
        cookie,
        String::new(),
        SecretBucket::User,
        form.key,
    )
    .await
    {
        Ok(()) => feedback(&headers, &query, "message", "secret-deleted"),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            private(login_redirect(PATH, &headers))
        }
        Err(error) if error.code == ErrorCode::PermissionDenied => {
            feedback(&headers, &query, "error", "not-authorized")
        }
        Err(error) if error.code == ErrorCode::NotFound => {
            feedback(&headers, &query, "error", "no-longer-available")
        }
        Err(_) => feedback(&headers, &query, "error", "outcome-unknown"),
    }
}

async fn render(
    state: &AppState,
    headers: &HeaderMap,
    identity: &IdentityUser,
    cookie: HeaderValue,
    query: &PageQuery,
    mut page: PersonalSecretsPageView,
    status: StatusCode,
) -> Response {
    let dashboard = match super::dashboard::personal_settings_shell_view_from_identity(
        state,
        identity,
        cookie.clone(),
        &query.org,
    )
    .await
    {
        Ok(view) => view,
        Err(error) => return identity_error(error, headers),
    };
    let cursor = if secrets_presets_connect::valid_user_secret_cursor(&query.cursor) {
        query.cursor.as_str()
    } else {
        page.error = approved_error("invalid-page").into();
        ""
    };
    page.account_id = identity.id.clone();
    page.action_query = context_query(&dashboard.selected_organization_slug, cursor);
    page.first_page_url = if cursor.is_empty() {
        String::new()
    } else {
        format!(
            "{PATH}{}",
            context_query(&dashboard.selected_organization_slug, "")
        )
    };
    if page.message.is_empty() {
        page.message = approved_message(&query.message).into();
    }
    if page.error.is_empty() {
        page.error = approved_error(&query.error).into();
    }
    match secrets_presets_connect::user_secret_page(state, cookie, cursor).await {
        Ok(inventory) => {
            page.available = true;
            page.secrets = inventory.secrets;
            if !inventory.next_cursor.is_empty() {
                page.next_page_url = format!(
                    "{PATH}{}",
                    context_query(
                        &dashboard.selected_organization_slug,
                        &inventory.next_cursor
                    )
                );
            }
        }
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return private(login_redirect(PATH, headers));
        }
        Err(error) if operational(error.code) => {}
        Err(error) if error.code == ErrorCode::InvalidArgument && !cursor.is_empty() => {
            page.error = approved_error("invalid-page").into();
        }
        Err(error) => return private(error_page(WebError::Connect(error))),
    }
    resolve_editor(&mut page);
    page.csrf_token = new_csrf_token();
    private(with_csrf_cookie(
        render_template(
            status,
            SettingsSecretsTemplate {
                view: &dashboard,
                page: &page,
            },
        ),
        csrf_cookie(&state.public_origin, &page.csrf_token),
    ))
}

fn resolve_editor(page: &mut PersonalSecretsPageView) {
    if !page.available {
        if !page.form.form_error.is_empty() {
            page.error = page.form.form_error.clone();
        }
        page.active_dialog.clear();
        return;
    }
    if page.active_dialog.is_empty() || page.active_dialog == "add-secret" {
        return;
    }
    if let Some(index) = page.secrets.iter().position(|row| row.key == page.form.key)
        && matches!(page.active_dialog.as_str(), "value" | "rename")
    {
        page.active_dialog = format!("secret-{}-{}", index + 1, page.active_dialog);
        return;
    }
    // Metadata may have changed while a write completed or failed ambiguously.
    // Never reopen an unrelated row at the same former position.
    page.error = if page.form.form_error.is_empty() {
        approved_error("no-longer-available").into()
    } else {
        page.form.form_error.clone()
    };
    page.active_dialog.clear();
}

fn validate_key(form: &mut SecretFormView) {
    if validate_workload_secret_key(&form.key).is_err() {
        form.key_error = format!(
            "Use 1–{MAX_WORKLOAD_SECRET_KEY_BYTES} ASCII letters, numbers or underscores; start with a letter or underscore."
        );
    }
}

fn operational(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Unavailable
            | ErrorCode::DeadlineExceeded
            | ErrorCode::ResourceExhausted
            | ErrorCode::Internal
            | ErrorCode::Unknown
    )
}

fn mutation_error(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::PermissionDenied => "You do not have permission to change these secrets.",
        ErrorCode::AlreadyExists => {
            "That key already exists. Choose another name or replace its value explicitly."
        }
        ErrorCode::NotFound => "That secret is no longer available. Review the refreshed list.",
        ErrorCode::InvalidArgument => {
            "The secret could not be accepted. Review its key and enter the value again."
        }
        _ => {
            "The change could not be confirmed. Review the refreshed list before trying again; values cannot be read back."
        }
    }
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "secret-saved" => "Secret saved. Storing it does not attach it to a sandbox.",
        "secret-renamed" => "Secret renamed. Review workloads that use the old key.",
        "secret-deleted" => {
            "Secret deleted. Values already projected into a running workload are not removed."
        }
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "account-changed" => {
            "Your account changed or this form expired. Review Secrets before trying again."
        }
        "invalid-key" => {
            "That secret key is invalid. Review the refreshed list before trying again."
        }
        "invalid-page" => "That secret page is no longer available. Return to the first page.",
        "not-authorized" => "You do not have permission to change these secrets.",
        "no-longer-available" => {
            "That secret is no longer available on this page. Review the refreshed list."
        }
        "outcome-unknown" => {
            "The change could not be confirmed. Review the refreshed list before trying again; values cannot be read back."
        }
        _ => "",
    }
}

fn context_query(org: &str, cursor: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if !org.is_empty() && org.len() <= 128 {
        query.append_pair("org", org);
    }
    if !cursor.is_empty() && secrets_presets_connect::valid_user_secret_cursor(cursor) {
        query.append_pair("cursor", cursor);
    }
    let query = query.finish();
    if query.is_empty() {
        query
    } else {
        format!("?{query}")
    }
}

fn feedback(headers: &HeaderMap, context: &PageQuery, key: &str, code: &str) -> Response {
    let mut query = context_query(&context.org, &context.cursor);
    query.push(if query.is_empty() { '?' } else { '&' });
    // Both feedback fields are fixed call-site literals, never upstream text.
    query.push_str(key);
    query.push('=');
    query.push_str(code);
    private(redirect(format!("{PATH}{query}"), headers))
}

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        // Native same-origin POSTs must retain their Origin for the strict
        // CSRF gate. no-referrer makes non-CORS form navigation send null.
        // Do not disclose this metadata-only page's URL to external sites.
        HeaderValue::from_static("same-origin"),
    );
    response
}

#[cfg(test)]
mod tests;
