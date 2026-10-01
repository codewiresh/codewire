use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use serde::Deserialize;

use crate::{
    account_sessions,
    account_two_factor::{self, Failure},
    auth::{IdentityUser, authenticated_identity, enforce_two_factor},
    error::WebError,
    response::{error_page, login_redirect, redirect, render_template, two_factor_redirect},
    security::{
        canonical_cookie, clear_scoped_cookie, csrf_cookie, page_csrf_token,
        request_has_same_origin, valid_csrf_token, with_csrf_cookie, with_response_cookie,
    },
    state::AppState,
    templates::SettingsTemplate,
    view::{AccountSessionRowView, DashboardView, SettingsPageView, TwoFactorDialogView},
};

const SETTINGS_PATH: &str = "/settings/";
const SECURITY_PATH: &str = "/settings/#security";
// Dialog identifiers. Only the two proof dialogs open from a URL; the others
// carry one-time values and exist only in the POST response that made them.
const REPLACE_DIALOG: &str = "replace-authenticator";
const CONFIRM_DIALOG: &str = "replace-authenticator-confirm";
const REPLACED_DIALOG: &str = "replace-authenticator-done";
const REGENERATE_DIALOG: &str = "regenerate-recovery-codes";
const REGENERATED_DIALOG: &str = "recovery-codes-done";

#[derive(Debug, Default, Deserialize)]
pub(super) struct SettingsQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    dialog: String,
    #[serde(default)]
    security: String,
    cursor: Option<String>,
}

struct AccountPage {
    dashboard: DashboardView,
    settings: SettingsPageView,
}

pub(super) async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
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
    let mut page = match account_page(
        &state,
        &headers,
        &identity,
        cookie,
        &query.org,
        query.cursor.as_deref(),
    )
    .await
    {
        Ok(page) => page,
        Err(response) => return response,
    };
    page.settings.message = approved_message(&query.message).to_owned();
    page.settings.error = approved_error(&query.error).to_owned();
    page.settings.security_error = approved_security_error(&query.security).to_owned();
    page.settings.two_factor.active =
        approved_dialog(&query.dialog, page.settings.two_factor_enabled);
    render_account(&state, &page, StatusCode::OK)
}

/// Read everything the Account page shows. Factor mutations call this before
/// they mutate: a confirmed replacement revokes the session the request
/// arrived with, so nothing can be read with it afterwards.
async fn account_page(
    state: &AppState,
    headers: &HeaderMap,
    identity: &IdentityUser,
    cookie: HeaderValue,
    selected_org: &str,
    cursor: Option<&str>,
) -> Result<AccountPage, Response> {
    let dashboard = match super::dashboard::personal_settings_shell_view_from_identity(
        state,
        headers,
        identity,
        cookie.clone(),
        selected_org,
    )
    .await
    {
        Ok(view) => view,
        Err(WebError::Unauthorized) => return Err(login_redirect(SETTINGS_PATH, headers)),
        Err(WebError::TwoFactorRequired) => {
            return Err(two_factor_redirect(SETTINGS_PATH, headers));
        }
        Err(error) => return Err(error_page(error)),
    };
    if cursor.is_some_and(|cursor| !account_sessions::valid_id(cursor)) {
        return Err(settings_redirect("invalid-session-page", true, headers));
    }
    let inventory = match account_sessions::inventory(state, cookie, &identity.id, cursor).await {
        Ok(inventory) => Some(inventory),
        Err(account_sessions::Failure::Unauthorized) => {
            return Err(login_redirect(SETTINGS_PATH, headers));
        }
        Err(_) => None,
    };
    let mut settings = SettingsPageView {
        account_id: identity.id.clone(),
        account_name: identity.display_name().into(),
        account_email: identity.email().into(),
        email_verified: identity.email_verified(),
        account_created: display_time(Some(identity.created_at())),
        two_factor_enabled: identity.two_factor_enabled(),
        first_sessions_url: format!("{}#sessions", SETTINGS_PATH.to_owned()),
        csrf_token: page_csrf_token(headers),
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
        settings.later_sessions_page = cursor.is_some_and(|cursor| !cursor.is_empty());
        if let Some(next) = inventory.next_cursor {
            let mut query_string = url::form_urlencoded::Serializer::new(String::new());
            query_string.append_pair("cursor", &next);
            settings.next_sessions_url =
                format!("{SETTINGS_PATH}?{}#sessions", query_string.finish());
        }
    }
    Ok(AccountPage {
        dashboard,
        settings,
    })
}

fn render_account(state: &AppState, page: &AccountPage, status: StatusCode) -> Response {
    private(with_csrf_cookie(
        render_template(
            status,
            SettingsTemplate {
                view: &page.dashboard,
                settings: &page.settings,
            },
        ),
        csrf_cookie(&state.public_origin, &page.settings.csrf_token),
    ))
}

fn approved_dialog(dialog: &str, two_factor_enabled: bool) -> &'static str {
    match dialog {
        REPLACE_DIALOG if two_factor_enabled => REPLACE_DIALOG,
        REGENERATE_DIALOG if two_factor_enabled => REGENERATE_DIALOG,
        _ => "",
    }
}

fn approved_security_error(code: &str) -> &'static str {
    match code {
        "account-changed" => {
            "Your account changed in another tab. Review Security before trying again. Nothing changed."
        }
        _ => "",
    }
}

// No Debug: the CSRF token, password and code are request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TwoFactorProofForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    password: String,
    proof: String,
}

// No Debug: the CSRF token and code are request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplaceConfirmForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    replacement_id: String,
    code: String,
}

#[derive(Clone, Copy)]
enum FactorChange {
    Replace,
    Regenerate,
}

/// The same boundary as session revocation, plus an enrolled factor. Every
/// page read happens here, before the IdP is asked to change anything.
async fn factor_change_page(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    account_id: &str,
) -> Result<(AccountPage, HeaderValue), Response> {
    if !account_sessions::cookie_authority_is_unique(headers) {
        return Err(private(login_redirect(SETTINGS_PATH, headers)));
    }
    if !account_sessions::mutation_origin_is_exact(headers, &state.public_origin)
        || !valid_csrf_token(headers, csrf)
    {
        return Err(private(error_page(WebError::CsrfRejected)));
    }
    let identity = match authenticated_identity(state, headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return Err(private(login_redirect(SETTINGS_PATH, headers))),
        Err(error) => return Err(private(error_page(error))),
    };
    if enforce_two_factor(&identity).is_err() {
        return Err(private(two_factor_redirect(SETTINGS_PATH, headers)));
    }
    if identity.id != account_id || !account_sessions::valid_id(account_id) {
        return Err(private(redirect(
            "/settings/?security=account-changed#security".into(),
            headers,
        )));
    }
    if !identity.two_factor_enabled() {
        // Nothing to replace; the Security card offers setup instead.
        return Err(private(redirect(SECURITY_PATH.into(), headers)));
    }
    let cookie =
        canonical_cookie(headers).map_err(|()| private(login_redirect(SETTINGS_PATH, headers)))?;
    let page = account_page(state, headers, &identity, cookie.clone(), "", None)
        .await
        .map_err(private)?;
    Ok((page, cookie))
}

fn failure_status(failure: Failure) -> StatusCode {
    match failure {
        Failure::ProofRejected | Failure::CodeRejected => StatusCode::UNPROCESSABLE_ENTITY,
        Failure::Locked => StatusCode::TOO_MANY_REQUESTS,
        Failure::Forbidden => StatusCode::FORBIDDEN,
        Failure::NotEnrolled | Failure::NoLongerAvailable => StatusCode::CONFLICT,
        Failure::Ended => StatusCode::GONE,
        Failure::Unauthorized => StatusCode::UNAUTHORIZED,
        Failure::Unavailable | Failure::UnknownOutcome => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Every message says what still works.
fn failure_copy(change: FactorChange, failure: Failure) -> &'static str {
    match (change, failure) {
        (FactorChange::Replace, Failure::ProofRejected) => {
            "The password or code didn't match. Nothing changed: your current authenticator and recovery codes still work."
        }
        (FactorChange::Regenerate, Failure::ProofRejected) => {
            "The password or code didn't match. Nothing changed: your current recovery codes still work."
        }
        (_, Failure::Locked) => {
            "Too many incorrect attempts. Wait 15 minutes, then try again. Your current authenticator and recovery codes still work."
        }
        (_, Failure::NotEnrolled) => {
            "Two-factor authentication isn't set up for this account, so there is nothing to change. Reload this page."
        }
        (_, Failure::Forbidden | Failure::Unauthorized) => {
            "This browser can't change two-factor authentication for this account. Reload this page. Nothing changed."
        }
        (_, Failure::CodeRejected) => {
            "That code doesn't match the new authenticator. Check the new Codewire entry in your app and try again. Your current authenticator still works."
        }
        (_, Failure::Ended) => {
            "This replacement ended after five incorrect codes or ten minutes. Start again. Your current authenticator still works."
        }
        (_, Failure::NoLongerAvailable) => {
            "This replacement is no longer available, for example because a newer one was started. Start again. Your current authenticator still works."
        }
        (FactorChange::Replace, Failure::Unavailable) => {
            "Authenticator replacement is unavailable right now. Nothing changed: your current authenticator and recovery codes still work."
        }
        (FactorChange::Regenerate, Failure::Unavailable) => {
            "Recovery codes can't be regenerated right now. Nothing changed: your current recovery codes still work."
        }
        (FactorChange::Replace, Failure::UnknownOutcome) => {
            "We couldn't confirm whether your authenticator was replaced. Reload this page. If you're asked to sign in, try your new authenticator first and then regenerate your recovery codes; if it isn't accepted, your current authenticator still works."
        }
        (FactorChange::Regenerate, Failure::UnknownOutcome) => {
            "We couldn't confirm whether new recovery codes were made. Your authenticator still works. Regenerate again to get a set you can save."
        }
    }
}

fn dialog_error(active: &'static str, error: &str) -> TwoFactorDialogView {
    TwoFactorDialogView {
        active,
        error: error.to_owned(),
        ..Default::default()
    }
}

pub(super) async fn replace_authenticator_start_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<TwoFactorProofForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (mut page, cookie) =
        match factor_change_page(&state, &headers, &form.csrf, &form.account_id).await {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
    match account_two_factor::start(
        &state,
        cookie,
        &form.account_id,
        &form.password,
        &form.proof,
    )
    .await
    {
        Ok(started) => {
            page.settings.two_factor = TwoFactorDialogView {
                active: CONFIRM_DIALOG,
                // The setup key below is always shown, so a QR rendering
                // failure never hides the new authenticator.
                qr_svg: super::authentication::totp_qr_svg(&started.totp_uri).unwrap_or_default(),
                setup_key: started.secret,
                replacement_id: started.replacement_id,
                expires: display_time(Some(&started.expires_at)),
                ..Default::default()
            };
            render_account(&state, &page, StatusCode::OK)
        }
        Err(Failure::Unauthorized) => private(login_redirect(SETTINGS_PATH, &headers)),
        Err(failure) => {
            page.settings.two_factor =
                dialog_error(REPLACE_DIALOG, failure_copy(FactorChange::Replace, failure));
            render_account(&state, &page, failure_status(failure))
        }
    }
}

pub(super) async fn replace_authenticator_confirm_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<ReplaceConfirmForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (mut page, cookie) =
        match factor_change_page(&state, &headers, &form.csrf, &form.account_id).await {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
    match account_two_factor::confirm(
        &state,
        cookie,
        &form.account_id,
        &form.replacement_id,
        &form.code,
    )
    .await
    {
        Ok(replaced) => {
            page.settings.two_factor = TwoFactorDialogView {
                active: REPLACED_DIALOG,
                backup_codes: replaced.backup_codes,
                ..Default::default()
            };
            // Every listed session, including this request's, is gone.
            page.settings.sessions_replaced = true;
            page.settings.sessions.clear();
            page.settings.current_session_listed = false;
            page.settings.next_sessions_url.clear();
            page.settings.later_sessions_page = false;
            let mut response = render_account(&state, &page, StatusCode::OK);
            if let Some(session_cookie) = replaced.session_cookie {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, session_cookie);
            }
            response
        }
        Err(Failure::Unauthorized) => private(login_redirect(SETTINGS_PATH, &headers)),
        Err(Failure::CodeRejected) => {
            // The setup key is never shown twice. The person can retry with the
            // authenticator they already added, or start again.
            page.settings.two_factor = TwoFactorDialogView {
                active: CONFIRM_DIALOG,
                error: failure_copy(FactorChange::Replace, Failure::CodeRejected).to_owned(),
                replacement_id: form.replacement_id,
                ..Default::default()
            };
            render_account(&state, &page, failure_status(Failure::CodeRejected))
        }
        Err(Failure::UnknownOutcome) => {
            page.settings.security_error =
                failure_copy(FactorChange::Replace, Failure::UnknownOutcome).to_owned();
            render_account(&state, &page, failure_status(Failure::UnknownOutcome))
        }
        Err(failure) => {
            page.settings.two_factor =
                dialog_error(REPLACE_DIALOG, failure_copy(FactorChange::Replace, failure));
            render_account(&state, &page, failure_status(failure))
        }
    }
}

pub(super) async fn regenerate_recovery_codes_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<TwoFactorProofForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (mut page, cookie) =
        match factor_change_page(&state, &headers, &form.csrf, &form.account_id).await {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
    match account_two_factor::regenerate(
        &state,
        cookie,
        &form.account_id,
        &form.password,
        &form.proof,
    )
    .await
    {
        Ok(backup_codes) => {
            page.settings.two_factor = TwoFactorDialogView {
                active: REGENERATED_DIALOG,
                backup_codes,
                ..Default::default()
            };
            render_account(&state, &page, StatusCode::OK)
        }
        Err(Failure::Unauthorized) => private(login_redirect(SETTINGS_PATH, &headers)),
        Err(failure) => {
            page.settings.two_factor = dialog_error(
                REGENERATE_DIALOG,
                failure_copy(FactorChange::Regenerate, failure),
            );
            render_account(&state, &page, failure_status(failure))
        }
    }
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

    fn enrolled_settings() -> SettingsPageView {
        SettingsPageView {
            account_id: "account-1".into(),
            csrf_token: "synthetic-csrf".into(),
            two_factor_enabled: true,
            sessions_available: true,
            current_session_id: "session-current".into(),
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
            ..Default::default()
        }
    }

    fn render(settings: &SettingsPageView) -> String {
        SettingsTemplate {
            view: &dashboard_view(),
            settings,
        }
        .render()
        .unwrap()
    }

    #[test]
    fn security_offers_factor_changes_only_for_an_enrolled_account() {
        let mut settings = enrolled_settings();
        settings.two_factor_enabled = false;
        let body = render(&settings);
        assert!(body.contains("Add a code from an authenticator app to every sign-in."));
        assert!(body.contains("href=\"/setup-2fa?return_to=%2Fsettings%2F\""));
        for absent in [
            "Replace authenticator",
            "Regenerate recovery codes",
            "/settings/_actions/two-factor/",
        ] {
            assert!(!body.contains(absent), "{absent}");
        }

        let body = render(&enrolled_settings());
        assert!(body.contains(
            "Sign-in asks for a code from your authenticator app. Recovery codes each work once."
        ));
        // Native GET launchers carry only the dialog name and work without
        // scripting; scripting opens the same dialog in place.
        for dialog in ["replace-authenticator", "regenerate-recovery-codes"] {
            assert!(body.contains(&format!(
                "<form class=\"cw-dialog-launcher\" method=\"get\" action=\"/settings/#{dialog}\"><input type=\"hidden\" name=\"dialog\" value=\"{dialog}\"><button"
            )));
            assert!(body.contains(&format!("data-dialog id=\"{dialog}\"")));
        }
        assert!(!body.contains("data-dialog-auto-open"));
        // One-time dialogs exist only in the POST response that made them.
        for one_time in [
            "replace-authenticator-confirm",
            "replace-authenticator-done",
            "recovery-codes-done",
            "data-testid=\"recovery-code\"",
        ] {
            assert!(!body.contains(one_time), "{one_time}");
        }
        // Proof fields are labelled, cleared on close and never prefilled.
        for id in [
            "replace-authenticator-password",
            "replace-authenticator-proof",
            "regenerate-recovery-codes-password",
            "regenerate-recovery-codes-proof",
        ] {
            assert!(body.contains(&format!("<label class=\"cw-label\" for=\"{id}\">")));
            let input = body.split(&format!("id=\"{id}\"")).nth(1).unwrap();
            let input = &input[..input.find('>').unwrap()];
            assert!(input.contains("data-dialog-private") && input.contains("required"));
            assert!(!input.contains("value="));
        }
        assert_eq!(body.matches("autocomplete=\"current-password\"").count(), 2);
    }

    #[test]
    fn url_launchers_open_only_proof_dialogs_for_an_enrolled_account() {
        assert_eq!(
            approved_dialog("replace-authenticator", true),
            "replace-authenticator"
        );
        assert_eq!(
            approved_dialog("regenerate-recovery-codes", true),
            "regenerate-recovery-codes"
        );
        for dialog in [
            "replace-authenticator-confirm",
            "replace-authenticator-done",
            "recovery-codes-done",
            "unknown",
        ] {
            assert_eq!(approved_dialog(dialog, true), "");
        }
        assert_eq!(approved_dialog("replace-authenticator", false), "");
        let mut settings = enrolled_settings();
        settings.two_factor.active = approved_dialog("regenerate-recovery-codes", true);
        let body = render(&settings);
        assert_eq!(body.matches("data-dialog-auto-open").count(), 1);
        assert!(body.contains(
            "id=\"regenerate-recovery-codes\" aria-labelledby=\"regenerate-recovery-codes-title\" data-dialog-auto-open"
        ));
        assert_eq!(approved_security_error("unknown"), "");
        assert!(approved_security_error("account-changed").contains("Nothing changed"));
    }

    #[test]
    fn one_time_values_are_escaped_and_shown_only_in_their_dialog() {
        let mut settings = enrolled_settings();
        settings.two_factor = TwoFactorDialogView {
            active: "replace-authenticator-confirm",
            replacement_id: "0123456789abcdef0123456789abcdef".into(),
            qr_svg: "<svg data-synthetic-qr></svg>".into(),
            setup_key: "<UNSAFE-KEY>".into(),
            expires: "October 1, 2026".into(),
            ..Default::default()
        };
        let body = render(&settings);
        assert_eq!(body.matches("data-dialog-auto-open").count(), 1);
        assert!(body.contains("id=\"replace-authenticator-confirm\" aria-labelledby=\"replace-authenticator-confirm-title\" data-dialog-auto-open"));
        assert!(body.contains("<svg data-synthetic-qr></svg>"));
        assert!(!body.contains("<UNSAFE-KEY>"));
        assert!(body.contains("&lt;UNSAFE-KEY&gt;") || body.contains("&#60;UNSAFE-KEY&#62;"));
        assert!(
            body.contains("name=\"replacement_id\" value=\"0123456789abcdef0123456789abcdef\"")
        );
        assert!(body.contains("Your current authenticator keeps working until you confirm."));

        // A rejected code reopens confirmation without the key or QR code.
        settings.two_factor.qr_svg.clear();
        settings.two_factor.setup_key.clear();
        settings.two_factor.error = "That code doesn't match the new authenticator.".into();
        let body = render(&settings);
        assert!(!body.contains("data-synthetic-qr") && !body.contains("UNSAFE-KEY"));
        assert!(
            body.contains("role=\"alert\">That code doesn&#39;t match")
                || body.contains("role=\"alert\">That code doesn&#x27;t match")
        );

        settings.two_factor = TwoFactorDialogView {
            active: "replace-authenticator-done",
            backup_codes: vec!["<unsafe-code>".into(), "0123456789".into()],
            ..Default::default()
        };
        settings.sessions_replaced = true;
        settings.sessions.clear();
        settings.current_session_listed = false;
        let body = render(&settings);
        assert_eq!(body.matches("data-testid=\"recovery-code\"").count(), 2);
        assert!(!body.contains("<unsafe-code>"));
        assert!(body.contains("<a class=\"cw-button\" href=\"/settings/#security\">Done</a>"));
        assert!(body.contains("Reload sessions"));
        assert!(!body.contains("session-other"));
        assert_eq!(body.matches("id=\"sign-out\"").count(), 1);
        assert!(!body.contains("Session controls are unavailable"));
    }
}

#[cfg(test)]
#[path = "account_two_factor_tests.rs"]
mod account_two_factor_tests;
