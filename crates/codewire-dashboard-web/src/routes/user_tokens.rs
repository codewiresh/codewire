//! The API keys page's User tokens group (#5688): the account's live user
//! tokens, and revoking one. Reads and revokes go to the IdP with the
//! browser-session cookie only (`account_user_tokens`).
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use serde::Deserialize;

use crate::{
    account_sessions::{self, Failure},
    account_user_tokens::{self, UserTokenRowView, UserTokensView},
    error::WebError,
    response::{error_page, login_redirect, redirect},
    state::AppState,
};

const PATH: &str = "/settings/api-keys/";

/// The group for one page of the account's tokens. A failed read shows the
/// group as unavailable rather than empty; an invalid cursor shows the first
/// page and says so.
pub(super) async fn read(
    state: &AppState,
    cookie: HeaderValue,
    account_id: &str,
    cursor: &str,
) -> UserTokensView {
    let valid = cursor.is_empty() || account_sessions::valid_id(cursor);
    let cursor = (valid && !cursor.is_empty()).then_some(cursor);
    let mut view = match account_user_tokens::inventory(state, cookie, account_id, cursor).await {
        Ok(inventory) => view(inventory, cursor),
        Err(_) => UserTokensView::default(),
    };
    if !valid {
        view.error = approved_error("invalid-user-token-page").into();
    }
    view
}

pub(super) fn view(
    inventory: account_user_tokens::Inventory,
    cursor: Option<&str>,
) -> UserTokensView {
    let time = |time: &str| super::settings::display_time(Some(time));
    let optional_time = |value: Option<String>| value.map(|value| time(&value)).unwrap_or_default();
    let mut view = UserTokensView {
        available: true,
        later_page: cursor.is_some_and(|cursor| !cursor.is_empty()),
        tokens: inventory
            .tokens
            .into_iter()
            .map(|token| UserTokenRowView {
                created: time(&token.created_at),
                expires: optional_time(token.expires_at),
                last_used: optional_time(token.last_used_at),
                id: token.id,
            })
            .collect(),
        ..Default::default()
    };
    if let Some(next) = inventory.next_cursor {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("token_cursor", &next);
        view.next_url = format!("{PATH}?{}#user-tokens", query.finish());
    }
    view
}

// No Debug: the CSRF field is request authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevokeForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    token_id: String,
}

pub(super) async fn revoke_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<RevokeForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return private(error_page(WebError::Forbidden));
    };
    if !account_sessions::cookie_authority_is_unique(&headers) {
        return private(login_redirect(PATH, &headers));
    }
    if !account_sessions::mutation_origin_is_exact(&headers, &state.public_origin) {
        return private(error_page(WebError::CsrfRejected));
    }
    let (identity, cookie) =
        match super::settings::mutation_identity(&state, &headers, &form.csrf, PATH).await {
            Ok(passed) => passed,
            Err(response) => return private(response),
        };
    if identity.id != form.account_id || !account_sessions::valid_id(&form.account_id) {
        return private(outcome_redirect(
            "user-token-account-changed",
            true,
            &headers,
        ));
    }
    let revoked =
        account_user_tokens::revoke(&state, cookie, &form.account_id, &form.token_id).await;
    private(revocation_response(&headers, revoked))
}

pub(super) fn revocation_response(headers: &HeaderMap, revoked: Result<(), Failure>) -> Response {
    match revoked {
        Ok(()) => outcome_redirect("user-token-revoked", false, headers),
        Err(Failure::Unauthorized) => login_redirect(PATH, headers),
        Err(Failure::Forbidden) => {
            outcome_redirect("user-token-controls-unavailable", true, headers)
        }
        Err(Failure::NoLongerAvailable) => {
            outcome_redirect("user-token-no-longer-available", true, headers)
        }
        Err(_) => outcome_redirect("user-token-outcome-unknown", true, headers),
    }
}

fn outcome_redirect(code: &str, error: bool, headers: &HeaderMap) -> Response {
    let key = if error { "error" } else { "message" };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(key, code);
    redirect(format!("{PATH}?{}#user-tokens", query.finish()), headers)
}

pub(super) fn approved_message(code: &str) -> &'static str {
    match code {
        "user-token-revoked" => "User token revoked.",
        _ => "",
    }
}

pub(super) fn approved_error(code: &str) -> &'static str {
    match code {
        "invalid-user-token-page" => {
            "That page of user tokens is invalid. Review the first page below."
        }
        "user-token-account-changed" => {
            "Your account changed. Review the refreshed list before trying again."
        }
        "user-token-controls-unavailable" => {
            "User token controls are unavailable. Reload before trying again."
        }
        "user-token-no-longer-available" => {
            "That user token is no longer available. Review the refreshed list below."
        }
        "user-token-outcome-unknown" => {
            "The revoke couldn't be confirmed. Review the refreshed list before trying again."
        }
        _ => "",
    }
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

#[cfg(test)]
#[path = "user_tokens_tests.rs"]
mod tests;
