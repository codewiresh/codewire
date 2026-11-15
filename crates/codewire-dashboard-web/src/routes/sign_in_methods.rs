//! The Account page's Sign-in methods card (#4062): the password and each
//! provider the IdP has configured, with Connect and Disconnect.
//!
//! Connect is a CSRF-checked POST. The IdP writes a single-use link row bound
//! to this account (session cookie and exact Origin only) and answers the
//! provider's authorize URL with the state cookie, which this action forwards
//! with a 303 to the provider. The provider returns to the IdP's callback,
//! which links only while this browser's session still belongs to the
//! account, and lands back here with a fixed code. Because Chromium applies a
//! page's form-action to a POST's redirect chain, the Account page adds
//! exactly the two provider origins to it (`render_account_settings_page`).
//!
//! An account with no password gets Add a password (#4528): a dialog whose
//! POST the IdP answers with a fixed code, shown here as fixed copy. The IdP
//! adds one only from a session that signed in within 10 minutes, with a
//! fresh second-factor code when one is enrolled.

use axum::{
    Form,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::{
    authentication::{PASSWORD_RULES, PASSWORDS_DIFFER, new_password_error, provider_label},
    settings::{display_time, mutation_cookie},
};
use crate::{
    account_sessions,
    account_sign_in_methods::{self, AddFailure, Failure, known_provider},
    auth::authenticated_identity,
    error::WebError,
    response::{error_page, login_redirect, redirect},
    state::AppState,
    view::{SignInMethodsView, SignInProviderView},
};

const SETTINGS_PATH: &str = "/settings/";
const SECTION: &str = "sign-in-methods";
/// The Add a password dialog's id, and the `dialog` value that opens it.
pub(super) const ADD_PASSWORD_DIALOG: &str = "add-password";

/// Read the card for `account_id`. A failed read shows a warning, never a
/// guess at what is connected.
pub(super) async fn view(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
) -> SignInMethodsView {
    match account_sign_in_methods::methods(state, cookie, account_id).await {
        Ok(methods) => methods_view(&methods),
        Err(_) => SignInMethodsView::default(),
    }
}

fn methods_view(methods: &account_sign_in_methods::Methods) -> SignInMethodsView {
    let configured: Vec<&'static str> = methods
        .providers
        .iter()
        .filter_map(|provider| known_provider(provider))
        .collect();
    let providers = configured
        .iter()
        .filter_map(|provider| {
            let label = provider_label(provider)?;
            let identity = methods
                .identities
                .iter()
                .find(|identity| identity.provider == *provider);
            let another_provider = methods.identities.iter().any(|other| {
                other.provider != *provider && configured.contains(&other.provider.as_str())
            });
            Some(SignInProviderView {
                provider,
                label,
                connected: identity.is_some(),
                account: identity
                    .and_then(|identity| identity.account.clone())
                    .unwrap_or_default(),
                connected_at: identity
                    .map(|identity| display_time(Some(&identity.linked_at)))
                    .unwrap_or_default(),
                can_disconnect: methods.password || another_provider,
            })
        })
        .collect();
    SignInMethodsView {
        available: true,
        password: methods.password,
        providers,
        message: String::new(),
        error: String::new(),
        ..Default::default()
    }
}

/// Open the Add a password dialog for `?dialog=add-password`, only on a card
/// that read an account with no password.
pub(super) fn apply_dialog(view: &mut SignInMethodsView, dialog: &str) {
    if dialog == ADD_PASSWORD_DIALOG && view.available && !view.password {
        view.add_password_open = true;
    }
}

/// The fixed messages for `?sign_in_method=<code>` after adding a password.
/// A refusal reopens the dialog with its message; anything else shows
/// nothing.
fn apply_password_notice(view: &mut SignInMethodsView, code: &str) -> bool {
    let error = match code {
        "password_added" => {
            view.message =
                "Password added. You can now sign in with your email address and this password."
                    .to_owned();
            return true;
        }
        "password_exists" => {
            view.error = "This account already has a password.".to_owned();
            return true;
        }
        "password_outcome_unknown" => {
            view.error =
                "We couldn't confirm whether your password was added. Review Password below before trying again."
                    .to_owned();
            return true;
        }
        "password_mismatch" => PASSWORDS_DIFFER,
        "password_rules" => PASSWORD_RULES,
        "password_reauthenticate" => {
            view.reauthenticate = true;
            "For your security, sign in again, then add your password within 10 minutes."
        }
        "password_code" => "That code didn't match. Nothing changed.",
        "password_locked" => "Too many incorrect attempts. Wait 15 minutes, then try again.",
        "password_unverified" => "Verify your email address before adding a password.",
        "password_failed" => "This browser can't add a password to this account. Reload this page.",
        _ => return false,
    };
    if view.available && !view.password {
        view.add_password_open = true;
        view.add_password_error = error.to_owned();
    }
    true
}

/// The fixed messages for `?sign_in_method=<code>&provider=<provider>`, from
/// the IdP's callback or the actions below. Anything else shows nothing.
pub(super) fn apply_notice(view: &mut SignInMethodsView, code: &str, provider: &str) {
    if apply_password_notice(view, code) {
        return;
    }
    let Some(label) = known_provider(provider).and_then(provider_label) else {
        return;
    };
    let (message, error) = match code {
        "connected" => (format!("{label} connected."), false),
        "disconnected" => (format!("{label} disconnected."), false),
        "cancelled" => (
            format!("Connecting {label} was cancelled. Nothing changed."),
            true,
        ),
        "expired" => (
            format!("Connecting {label} took too long or was already used. Try again."),
            true,
        ),
        "unverified_email" => (
            format!(
                "{label} didn't share a verified email address, so it wasn't connected. Verify your email with {label}, then try again."
            ),
            true,
        ),
        "unavailable" => (
            format!("Signing in with {label} isn't available right now. Nothing changed."),
            true,
        ),
        "taken" => (
            format!("That {label} account is already connected to another Codewire account."),
            true,
        ),
        "already_connected" => (
            format!("Another {label} account is already connected. Disconnect it first."),
            true,
        ),
        "session_changed" => (
            format!(
                "Your session changed while connecting {label}, so nothing was connected. Try again."
            ),
            true,
        ),
        "failed" => (format!("{label} couldn't be connected. Try again."), true),
        "last_method" => (
            "Add a password or connect another provider first.".to_owned(),
            true,
        ),
        "not_connected" => (
            format!("{label} isn't connected. Review the list below."),
            true,
        ),
        "outcome_unknown" => (
            "The change couldn't be confirmed. Review the list below before trying again."
                .to_owned(),
            true,
        ),
        _ => return,
    };
    if error {
        view.error = message;
    } else {
        view.message = message;
    }
}

fn section_redirect(code: &str, provider: &str, headers: &HeaderMap) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("sign_in_method", code)
        .append_pair("provider", provider)
        .finish();
    redirect(format!("{SETTINGS_PATH}?{query}#{SECTION}"), headers)
}

// No Debug: the CSRF token is request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    provider: String,
}

/// The session, two-factor, Origin and CSRF boundary of the account
/// controls, and the account this page was rendered for.
#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn authorized(
    state: &AppState,
    headers: &HeaderMap,
    form: &ProviderForm,
) -> Result<(HeaderValue, &'static str), Response> {
    let cookie = authorized_account(state, headers, &form.csrf, &form.account_id).await?;
    let Some(provider) = known_provider(&form.provider) else {
        return Err(private(redirect(
            format!("{SETTINGS_PATH}#{SECTION}"),
            headers,
        )));
    };
    Ok((cookie, provider))
}

/// The account controls' boundary for `account_id`, which must be the
/// signed-in account this page was rendered for.
#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn authorized_account(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    account_id: &str,
) -> Result<HeaderValue, Response> {
    if !account_sessions::cookie_authority_is_unique(headers) {
        return Err(private(login_redirect(SETTINGS_PATH, headers)));
    }
    if !account_sessions::mutation_origin_is_exact(headers, &state.public_origin) {
        return Err(private(error_page(WebError::CsrfRejected)));
    }
    let identity = match authenticated_identity(state, headers).await {
        Ok(identity) => identity,
        Err(WebError::Unauthorized) => return Err(private(login_redirect(SETTINGS_PATH, headers))),
        Err(error) => return Err(private(error_page(error))),
    };
    let cookie = mutation_cookie(state, headers, csrf, SETTINGS_PATH)
        .await
        .map_err(private)?;
    if identity.id != account_id || !account_sessions::valid_id(account_id) {
        return Err(private(redirect(
            "/settings/?security=account-changed#security".into(),
            headers,
        )));
    }
    Ok(cookie)
}

pub(super) async fn connect_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<ProviderForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (cookie, provider) = match authorized(&state, &headers, &form).await {
        Ok(authorized) => authorized,
        Err(response) => return response,
    };
    match account_sign_in_methods::start_link(&state, cookie, &form.account_id, provider).await {
        // A plain 303 to the provider, even for an htmx request: the browser
        // must leave this origin with the state cookie.
        Ok(started) => {
            let mut response = see_other(&started.location);
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, started.state_cookie);
            private(response)
        }
        Err(Failure::Unauthorized) => private(login_redirect(SETTINGS_PATH, &headers)),
        Err(Failure::NotFound) => private(section_redirect("unavailable", provider, &headers)),
        Err(Failure::Conflict) => {
            private(section_redirect("already_connected", provider, &headers))
        }
        Err(Failure::Forbidden) => private(section_redirect("session_changed", provider, &headers)),
        Err(Failure::Unavailable) => private(section_redirect("failed", provider, &headers)),
    }
}

pub(super) async fn disconnect_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<ProviderForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let (cookie, provider) = match authorized(&state, &headers, &form).await {
        Ok(authorized) => authorized,
        Err(response) => return response,
    };
    let code =
        match account_sign_in_methods::unlink(&state, cookie, &form.account_id, provider).await {
            Ok(()) => "disconnected",
            Err(Failure::Unauthorized) => return private(login_redirect(SETTINGS_PATH, &headers)),
            Err(Failure::Conflict) => "last_method",
            Err(Failure::NotFound) => "not_connected",
            Err(Failure::Forbidden) => "session_changed",
            Err(Failure::Unavailable) => "outcome_unknown",
        };
    private(section_redirect(code, provider, &headers))
}

// No Debug: the CSRF token, password and code are request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AddPasswordForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    new_password: String,
    confirm_password: String,
    #[serde(default)]
    code: String,
}

fn password_redirect(code: &str, headers: &HeaderMap) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("sign_in_method", code)
        .finish();
    redirect(format!("{SETTINGS_PATH}?{query}#{SECTION}"), headers)
}

/// Add a password to an account that signs in only with a provider (#4528).
/// The IdP decides; this checks the form and names its answer.
pub(super) async fn add_password_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<AddPasswordForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    let cookie = match authorized_account(&state, &headers, &form.csrf, &form.account_id).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if let Some(error) = new_password_error(&form.new_password, &form.confirm_password) {
        let code = if error == PASSWORDS_DIFFER {
            "password_mismatch"
        } else {
            "password_rules"
        };
        return private(password_redirect(code, &headers));
    }
    let code = match account_sign_in_methods::add_password(
        &state,
        cookie,
        &form.account_id,
        &form.new_password,
        form.code.trim(),
    )
    .await
    {
        Ok(()) => "password_added",
        Err(AddFailure::Unauthorized) => return private(login_redirect(SETTINGS_PATH, &headers)),
        Err(AddFailure::Reauthenticate) => "password_reauthenticate",
        Err(AddFailure::Unverified) => "password_unverified",
        Err(AddFailure::Exists) => "password_exists",
        Err(AddFailure::CodeRejected) => "password_code",
        Err(AddFailure::Locked) => "password_locked",
        Err(AddFailure::Refused) => "password_rules",
        Err(AddFailure::Forbidden) => "password_failed",
        Err(AddFailure::Unavailable) => "password_outcome_unknown",
    };
    private(password_redirect(code, &headers))
}

fn see_other(location: &str) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(location) = HeaderValue::from_str(location) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    response
}

fn private(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(axum::http::header::VARY, HeaderValue::from_static("Cookie"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_sign_in_methods::Methods;

    fn methods(body: serde_json::Value) -> Methods {
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn only_configured_providers_appear_and_the_last_way_in_stays() {
        let view = methods_view(&methods(serde_json::json!({
            "account_id": "account-1", "providers": ["github"], "password": false,
            "identities": [
                { "provider": "github", "account": "octocat", "linked_at": "2026-11-12T09:30:00Z" },
                { "provider": "google", "account": "person@example.test", "linked_at": "2026-11-12T09:31:00Z" }
            ]
        })));
        assert!(view.available);
        assert_eq!(view.providers.len(), 1, "Google is not configured");
        let github = &view.providers[0];
        assert_eq!((github.provider, github.label), ("github", "GitHub"));
        assert!(github.connected);
        assert_eq!(github.account, "octocat");
        assert!(
            !github.can_disconnect,
            "an unconfigured provider is no way in"
        );

        let view = methods_view(&methods(serde_json::json!({
            "account_id": "account-1", "providers": ["github", "google"], "password": false,
            "identities": [
                { "provider": "github", "account": null, "linked_at": "2026-11-12T09:30:00Z" },
                { "provider": "google", "account": "person@example.test", "linked_at": "2026-11-12T09:31:00Z" }
            ]
        })));
        assert!(
            view.providers
                .iter()
                .all(|provider| provider.can_disconnect)
        );
        assert_eq!(view.providers[0].account, "");
    }

    #[test]
    fn notices_are_fixed_copy_for_known_codes_and_providers() {
        let mut view = SignInMethodsView::default();
        apply_notice(&mut view, "connected", "github");
        assert_eq!(view.message, "GitHub connected.");
        let mut view = SignInMethodsView::default();
        apply_notice(&mut view, "taken", "github");
        assert_eq!(
            view.error,
            "That GitHub account is already connected to another Codewire account."
        );
        let mut view = SignInMethodsView::default();
        apply_notice(&mut view, "last_method", "google");
        assert_eq!(
            view.error,
            "Add a password or connect another provider first."
        );
        for (code, provider) in [
            ("connected", "gitlab"),
            ("<script>", "github"),
            ("", "github"),
        ] {
            let mut view = SignInMethodsView::default();
            apply_notice(&mut view, code, provider);
            assert!(view.message.is_empty() && view.error.is_empty());
        }
    }
}

#[cfg(test)]
#[path = "sign_in_methods_tests.rs"]
mod route_tests;
