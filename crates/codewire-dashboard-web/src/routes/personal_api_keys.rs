use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Form,
    extract::{
        Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_proto::codewire::v1::ApiKey;
use connectrpc::ErrorCode;
use serde::Deserialize;
use tokio::{
    task::JoinSet,
    time::{Instant, timeout_at},
};

use crate::{
    account_sessions,
    auth::{authenticated_identity, enforce_two_factor},
    error::WebError,
    personal_api_keys_connect as api,
    response::{error_page, login_redirect, redirect, render_template, two_factor_redirect},
    security::{canonical_cookie, csrf_cookie, valid_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::SettingsApiKeysTemplate,
    time_display::calendar_datetime,
    view::{
        ApiKeyRow, DashboardView, PersonalApiKeyFormView, PersonalApiKeyGroupView,
        PersonalApiKeyRow, PersonalApiKeysPageView,
    },
};

const PATH: &str = "/settings/api-keys/";
const ORGANIZATIONS_PER_PAGE: usize = 20;
const KEYS_PER_GROUP: usize = 100;
const LIST_CONCURRENCY: usize = 4;
const INVENTORY_BUDGET: Duration = Duration::from_secs(10);

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    search: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    organization: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

// Request authority is never retained in a diagnostic model.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    org_id: String,
    name: String,
    expiration: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToggleForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    org_id: String,
    key_id: String,
    disabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    org_id: String,
    key_id: String,
}

struct PageContext {
    account_id: String,
    cookie: HeaderValue,
    view: DashboardView,
    organizations_available: bool,
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn context(
    state: &AppState,
    headers: &HeaderMap,
    query: &PageQuery,
    expected_account: Option<&str>,
) -> Result<PageContext, Response> {
    if !account_sessions::cookie_authority_is_unique(headers) {
        return Err(private(login_redirect(PATH, headers)));
    }
    let cookie = canonical_cookie(headers).map_err(|()| private(login_redirect(PATH, headers)))?;
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(|error| web_error(error, headers))?;
    enforce_two_factor(&identity).map_err(|error| web_error(error, headers))?;
    if !account_sessions::valid_id(&identity.id) {
        return Err(private(error_page(WebError::IdentityUnavailable)));
    }
    if expected_account.is_some_and(|account| account != identity.id) {
        return Err(feedback(
            headers,
            &PageQuery::default(),
            "error",
            "account-changed",
        ));
    }
    let (mut organizations, available) = match api::organizations(state, cookie.clone()).await {
        Ok(rows) => (rows, true),
        Err(error) if operational(error.code) => (Vec::new(), false),
        Err(error) => return Err(web_error(WebError::Connect(error), headers)),
    };
    organizations.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then(left.id.cmp(&right.id))
    });
    let view = super::dashboard::personal_settings_shell_view_from_organizations(
        state,
        headers,
        &identity,
        cookie.clone(),
        &query.org,
        organizations,
        !available,
    )
    .await
    .map_err(|error| web_error(error, headers))?;
    Ok(PageContext {
        account_id: identity.id,
        cookie,
        view,
        organizations_available: available,
    })
}

pub(super) async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return feedback(&headers, &PageQuery::default(), "error", "invalid-page");
    };
    let context = match context(&state, &headers, &query, None).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    inventory_response(
        &state,
        &headers,
        &context,
        &query,
        PersonalApiKeysPageView::default(),
        StatusCode::OK,
    )
    .await
}

async fn inventory_response(
    state: &AppState,
    headers: &HeaderMap,
    context: &PageContext,
    query: &PageQuery,
    mut page: PersonalApiKeysPageView,
    status: StatusCode,
) -> Response {
    let cursor_index = context
        .view
        .organizations
        .iter()
        .position(|org| org.id == query.cursor);
    let start = if query.cursor.is_empty() {
        0
    } else if let Some(index) = cursor_index {
        index + 1
    } else {
        page.error = approved_error("invalid-page").into();
        0
    };
    let end = (start + ORGANIZATIONS_PER_PAGE).min(context.view.organizations.len());
    if start > 0 {
        page.first_page_url = format!("{PATH}{}", context_query(""));
    }
    if end < context.view.organizations.len() {
        page.next_page_url = format!(
            "{PATH}{}",
            context_query(&context.view.organizations[end - 1].id)
        );
    }
    page.action_query = context_query(if start > 0 { &query.cursor } else { "" });
    if start > 0 {
        page.cursor.clone_from(&query.cursor);
    }
    page.filter = crate::view::ApiKeyFilterView::new(&query.search, &query.status);
    // Only an organization on this page narrows the list; anything else shows all.
    if context.view.organizations[start..end]
        .iter()
        .any(|org| org.id == query.organization)
    {
        page.filter.organization.clone_from(&query.organization);
    }
    if context.organizations_available {
        page.groups = context.view.organizations[start..end]
            .iter()
            .cloned()
            .map(|organization| PersonalApiKeyGroupView {
                organization,
                keys: Vec::new(),
                available: false,
                truncated: false,
            })
            .collect();
        if let Err(error) = load_groups(
            state,
            &context.cookie,
            &context.account_id,
            &mut page.groups,
        )
        .await
        {
            return web_error(WebError::Connect(error), headers);
        }
    }
    if page.error.is_empty() {
        page.error = approved_error(&query.error).into();
    }
    if page.message.is_empty() {
        page.message = approved_message(&query.message).into();
    }
    render(state, context, page, status)
}

async fn load_groups(
    state: &AppState,
    cookie: &HeaderValue,
    account_id: &str,
    groups: &mut [PersonalApiKeyGroupView],
) -> Result<(), connectrpc::ConnectError> {
    load_groups_until(
        state,
        cookie,
        account_id,
        groups,
        Instant::now() + INVENTORY_BUDGET,
    )
    .await
}

async fn load_groups_until(
    state: &AppState,
    cookie: &HeaderValue,
    account_id: &str,
    groups: &mut [PersonalApiKeyGroupView],
    deadline: Instant,
) -> Result<(), connectrpc::ConnectError> {
    let mut tasks = JoinSet::new();
    let mut next = 0;
    loop {
        while next < groups.len() && tasks.len() < LIST_CONCURRENCY {
            let state = state.clone();
            let cookie = cookie.clone();
            let account = account_id.to_owned();
            let org = groups[next].organization.id.clone();
            let index = next;
            tasks.spawn(async move {
                (
                    index,
                    api::list_for_user(&state, cookie, &org, &account).await,
                )
            });
            next += 1;
        }
        if tasks.is_empty() {
            break;
        }
        match timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok((index, Ok(keys))))) => {
                // The adapter validates the entire response and filters actor
                // ownership before this presentation-only truncation.
                groups[index].truncated = keys.len() > KEYS_PER_GROUP;
                groups[index].keys = keys.into_iter().take(KEYS_PER_GROUP).map(key_row).collect();
                groups[index].available = true;
            }
            Ok(Some(Ok((_, Err(error))))) if operational(error.code) => {}
            Ok(Some(Ok((_, Err(error))))) => return Err(error),
            Ok(Some(Err(_))) => {
                return Err(connectrpc::ConnectError::unavailable(
                    "inventory unavailable",
                ));
            }
            Ok(None) => break,
            Err(_) => {
                // Dropping JoinSet aborts outstanding reads. Unstarted and
                // unfinished groups stay explicitly unavailable, never empty.
                break;
            }
        }
    }
    Ok(())
}

fn key_row(key: ApiKey) -> PersonalApiKeyRow {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64);
    let disabled = key.disabled_at.is_set();
    let expires = key.expires_at.into_option();
    let expired = expires.as_ref().is_some_and(|value| value.seconds <= now);
    let (status, status_tone) = if disabled {
        ("Disabled", "warning")
    } else if expired {
        ("Expired", "danger")
    } else {
        ("Active", "success")
    };
    PersonalApiKeyRow {
        key: ApiKeyRow {
            id: key.id,
            name: key.name,
            prefix: format!("cw_{}…", key.key_prefix),
            created_by: "You".into(),
            created: key.created_at.into_option().map_or_else(
                || "Unknown".into(),
                |value| calendar_datetime(value.seconds),
            ),
            last_used: key
                .last_used_at
                .into_option()
                .map_or_else(|| "Never".into(), |value| calendar_datetime(value.seconds)),
            status,
            status_tone,
            disabled,
            expired,
        },
        expires: expires.map_or_else(|| "Never".into(), |value| calendar_datetime(value.seconds)),
    }
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn mutation_context(
    state: &AppState,
    headers: &HeaderMap,
    query: &PageQuery,
    csrf: &str,
    account: &str,
) -> Result<PageContext, Response> {
    if !account_sessions::mutation_origin_is_exact(headers, &state.public_origin)
        || !valid_csrf_token(headers, csrf)
    {
        return Err(private(error_page(WebError::CsrfRejected)));
    }
    if !account_sessions::valid_id(account) {
        return Err(feedback(
            headers,
            &PageQuery::default(),
            "error",
            "account-changed",
        ));
    }
    context(state, headers, query, Some(account)).await
}

pub(super) async fn create_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
    form: Result<Form<CreateForm>, FormRejection>,
) -> Response {
    let (Ok(Query(query)), Ok(Form(form))) = (query, form) else {
        return private(error_page(WebError::Forbidden));
    };
    let context =
        match mutation_context(&state, &headers, &query, &form.csrf, &form.account_id).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let mut page = PersonalApiKeysPageView {
        form: PersonalApiKeyFormView {
            org_id: form.org_id,
            name: form.name.trim().into(),
            expiration: form.expiration,
            expanded: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let organization = context
        .view
        .organizations
        .iter()
        .find(|org| org.id == page.form.org_id);
    let expires = match page.form.expiration.as_str() {
        "never" => Some(None),
        "30" => Some(Some(30)),
        "60" => Some(Some(60)),
        "90" => Some(Some(90)),
        _ => None,
    };
    if !context.organizations_available {
        page.form.error = "Organizations are unavailable. Reload before creating a key.".into();
    } else if organization.is_none() {
        page.form.error = "Choose an organization you currently belong to.".into();
    } else if page.form.name.is_empty()
        || page.form.name.len() > 128
        || page.form.name.chars().any(char::is_control)
    {
        page.form.error =
            "Enter a key name of at most 128 bytes, without control characters.".into();
    } else if expires.is_none() {
        page.form.error = "Choose a supported expiration.".into();
    }
    if page.form.error.is_empty() {
        let organization = organization.expect("validated membership");
        match api::create_for_user(
            &state,
            context.cookie.clone(),
            &organization.id,
            &context.account_id,
            &page.form.name,
            expires.expect("validated expiration"),
        )
        .await
        {
            Ok(created) => {
                // Everything needed to render was read before Create. An
                // optional metadata outage cannot consume the sole raw key.
                page.one_time_key = created.key;
                page.one_time_name = created.metadata.name;
                page.one_time_organization = organization.name.clone();
                page.form = PersonalApiKeyFormView::default();
                return render(&state, &context, page, StatusCode::OK);
            }
            Err(error) if error.code == ErrorCode::Unauthenticated => {
                return private(login_redirect(PATH, &headers));
            }
            Err(error) if error.code == ErrorCode::InvalidArgument => {
                page.form.error =
                    "The key could not be accepted. Review the name, organization and expiration."
                        .into();
            }
            Err(error) => {
                return feedback(
                    &headers,
                    &query,
                    "error",
                    match error.code {
                        ErrorCode::PermissionDenied => "not-authorized",
                        ErrorCode::NotFound => "no-longer-available",
                        // A dispatched Create may have succeeded without a usable
                        // acknowledgment. PRG prevents refresh from resubmitting it.
                        _ => "create-outcome-unknown",
                    },
                );
            }
        }
    }
    inventory_response(
        &state,
        &headers,
        &context,
        &query,
        page,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await
}

pub(super) async fn toggle_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
    form: Result<Form<ToggleForm>, FormRejection>,
) -> Response {
    let (Ok(Query(query)), Ok(Form(form))) = (query, form) else {
        return private(error_page(WebError::Forbidden));
    };
    let context =
        match mutation_context(&state, &headers, &query, &form.csrf, &form.account_id).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if let Err(response) = owned_key(
        &state,
        &headers,
        &context,
        &query,
        &form.org_id,
        &form.key_id,
        false,
    )
    .await
    {
        return response;
    }
    mutation_result(
        &headers,
        &query,
        api::update_for_user(
            &state,
            context.cookie,
            &form.org_id,
            &context.account_id,
            &form.key_id,
            form.disabled,
        )
        .await,
        if form.disabled {
            "key-disabled"
        } else {
            "key-enabled"
        },
    )
}

pub(super) async fn delete_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
    form: Result<Form<DeleteForm>, FormRejection>,
) -> Response {
    let (Ok(Query(query)), Ok(Form(form))) = (query, form) else {
        return private(error_page(WebError::Forbidden));
    };
    let context =
        match mutation_context(&state, &headers, &query, &form.csrf, &form.account_id).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if let Err(response) = owned_key(
        &state,
        &headers,
        &context,
        &query,
        &form.org_id,
        &form.key_id,
        true,
    )
    .await
    {
        return response;
    }
    mutation_result(
        &headers,
        &query,
        api::delete(&state, context.cookie, &form.org_id, &form.key_id).await,
        "key-deleted",
    )
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn owned_key(
    state: &AppState,
    headers: &HeaderMap,
    context: &PageContext,
    query: &PageQuery,
    org_id: &str,
    key_id: &str,
    require_admin: bool,
) -> Result<(), Response> {
    if !context.organizations_available {
        return Err(feedback(headers, query, "error", "unavailable"));
    }
    let organization = context
        .view
        .organizations
        .iter()
        .find(|org| org.id == org_id);
    let Some(organization) = organization.filter(|_| account_sessions::valid_id(key_id)) else {
        return Err(feedback(headers, query, "error", "no-longer-available"));
    };
    if require_admin && !organization.can_admin {
        return Err(feedback(headers, query, "error", "not-authorized"));
    }
    // Never authorize from the displayed/capped inventory. The fresh full
    // response is validated and filtered for the exact authenticated actor.
    match api::list_for_user(state, context.cookie.clone(), org_id, &context.account_id).await {
        Ok(keys) if keys.iter().any(|key| key.id == key_id) => Ok(()),
        Ok(_) => Err(feedback(headers, query, "error", "no-longer-available")),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            Err(private(login_redirect(PATH, headers)))
        }
        Err(error) if error.code == ErrorCode::PermissionDenied => {
            Err(feedback(headers, query, "error", "not-authorized"))
        }
        Err(_) => Err(feedback(headers, query, "error", "unavailable")),
    }
}

fn render(
    state: &AppState,
    context: &PageContext,
    mut page: PersonalApiKeysPageView,
    status: StatusCode,
) -> Response {
    page.account_id = context.account_id.clone();
    page.organizations = context.view.organizations.clone();
    page.organizations_available = context.organizations_available;
    page.reload_url = format!("{PATH}{}", context_query(""));
    page.csrf_token = context.view.csrf_token.to_string();
    let response = with_csrf_cookie(
        render_template(
            status,
            SettingsApiKeysTemplate {
                view: &context.view,
                page: &page,
            },
        ),
        csrf_cookie(&state.public_origin, &page.csrf_token),
    );
    private(response)
}

fn mutation_result(
    headers: &HeaderMap,
    query: &PageQuery,
    result: Result<(), connectrpc::ConnectError>,
    message: &str,
) -> Response {
    match result {
        Ok(()) => feedback(headers, query, "message", message),
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            private(login_redirect(PATH, headers))
        }
        Err(error) => feedback(
            headers,
            query,
            "error",
            match error.code {
                ErrorCode::PermissionDenied => "not-authorized",
                ErrorCode::NotFound => "no-longer-available",
                _ => "outcome-unknown",
            },
        ),
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

fn web_error(error: WebError, headers: &HeaderMap) -> Response {
    private(match error {
        WebError::Unauthorized => login_redirect(PATH, headers),
        WebError::TwoFactorRequired => two_factor_redirect(PATH, headers),
        WebError::Connect(error) if error.code == ErrorCode::Unauthenticated => {
            login_redirect(PATH, headers)
        }
        WebError::Connect(error) if error.code == ErrorCode::PermissionDenied => {
            error_page(WebError::Forbidden)
        }
        error => error_page(error),
    })
}

fn approved_message(code: &str) -> &'static str {
    match code {
        "key-disabled" => "Key disabled. Integrations using it can no longer authenticate.",
        "key-enabled" => "Key enabled. Integrations can use it with your current permissions.",
        "key-deleted" => {
            "Key permanently deleted. Integrations using it can no longer authenticate."
        }
        _ => "",
    }
}

fn approved_error(code: &str) -> &'static str {
    match code {
        "account-changed" => {
            "Your account changed or the form expired. Review your API keys before trying again."
        }
        "invalid-page" => "That organization page is no longer available. Showing the first page.",
        "not-authorized" => {
            "You do not have permission for this action. Deleting a key requires an organization owner or administrator."
        }
        "no-longer-available" => {
            "That key or organization is no longer available to this account. Review the refreshed inventory."
        }
        "unavailable" => {
            "The key's ownership could not be verified. No change was attempted; reload before trying again."
        }
        "outcome-unknown" => {
            "The change could not be confirmed. Review the current key status before trying again."
        }
        "create-outcome-unknown" => {
            "Creation could not be confirmed. Review this inventory before trying again. If a key was created without its value being returned, disable it or ask an organization administrator to delete it before creating a replacement."
        }
        _ => "",
    }
}

fn context_query(cursor: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if account_sessions::valid_id(cursor) {
        query.append_pair("cursor", cursor);
    }
    let query = query.finish();
    if query.is_empty() {
        query
    } else {
        format!("?{query}")
    }
}

fn feedback(headers: &HeaderMap, query: &PageQuery, key: &str, code: &str) -> Response {
    let mut query = context_query(&query.cursor);
    query.push(if query.is_empty() { '?' } else { '&' });
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
        HeaderValue::from_static("same-origin"),
    );
    response
}

#[cfg(test)]
mod tests;
