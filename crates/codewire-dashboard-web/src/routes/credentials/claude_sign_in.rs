//! The dashboard's Claude sign-in (#4935). Start keeps the sealed handle in a
//! cookie scoped to these two actions and shows Claude's authorize page.
//! Complete sends the handle back with the pasted `code#state`. The handle
//! never reaches the page or a URL, and the pasted code is never shown again.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Form, extract::State, http::HeaderMap, response::Response};
use serde::Deserialize;

use super::{
    CredentialQuery, QueryParameters, RejectedAddition, addition_error, exact_id, mutation_cookie,
    page_redirect, render_page, row_action_dialog, valid_credential_name, valid_generation,
};
use crate::credentials_connect::{self, ClaudeSignInRefusal, CredentialSettingsData};
use crate::security::{
    claude_sign_in_cookie, claude_sign_in_handle, clear_claude_sign_in_cookie, with_response_cookie,
};
use crate::state::AppState;

const NEW_DIALOG: &str = "add-claude-sign-in";

/// The dialog's code step: the field for the pasted code, and Claude's
/// authorize page when the sign-in has just started.
pub(super) struct CodeStep<'a> {
    pub(super) authorize_url: &'a str,
}

// Deliberately not Debug. Both reconnect fields are present together to
// reconnect an exact sign-in.
#[derive(Deserialize)]
pub(in crate::routes) struct StartSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    expected_revocation_generation: Option<u64>,
}

// Deliberately not Debug: the pasted code is write-only.
#[derive(Deserialize)]
pub(in crate::routes) struct CompleteSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    code: String,
    #[serde(default)]
    credential_id: String,
    #[serde(default)]
    expected_revocation_generation: Option<u64>,
}

type Reconnect = Option<(String, u64)>;

/// The dialog a submission belongs to and the exact sign-in it reconnects, or
/// `None` for a half-given or malformed reconnect.
fn target(credential_id: &str, generation: Option<u64>) -> Option<(String, Reconnect)> {
    match (credential_id.is_empty(), generation) {
        (true, None) => Some((NEW_DIALOG.to_owned(), None)),
        (false, Some(generation))
            if exact_id(credential_id).is_ok() && valid_generation(generation, true) =>
        {
            Some((
                row_action_dialog("credential", credential_id, "reconnect"),
                Some((credential_id.to_owned(), generation)),
            ))
        }
        _ => None,
    }
}

async fn reopen(
    state: &AppState,
    headers: &HeaderMap,
    query: &QueryParameters,
    dialog: &str,
    error: &'static str,
    name: &str,
    sign_in: Option<CodeStep<'_>>,
) -> Response {
    let rejected = RejectedAddition {
        dialog,
        error,
        name,
        sign_in,
        antigravity_sign_in: None,
    };
    render_page(state, headers, query, Some(rejected)).await
}

pub(in crate::routes) async fn start_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<StartSubmission>,
) -> Response {
    let target = target(&form.credential_id, form.expected_revocation_generation);
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let Some((dialog, _)) = target.filter(|_| valid_credential_name(name)) else {
        let error = "credential-invalid";
        return reopen(&state, &headers, &query, NEW_DIALOG, error, name, None).await;
    };
    let started = match credentials_connect::start_claude_sign_in(&state, cookie).await {
        Ok(started) => started,
        Err(error) => {
            return addition_error(&state, &headers, &query, &dialog, name, error.code).await;
        }
    };
    let max_age = started.expires_at_unix.saturating_sub(unix_now());
    let Some(handle_cookie) = u32::try_from(max_age)
        .ok()
        .and_then(|max_age| claude_sign_in_cookie(&state.public_origin, &started.handle, max_age))
    else {
        let error = "credential-request-failed";
        return reopen(&state, &headers, &query, &dialog, error, name, None).await;
    };
    let step = CodeStep {
        authorize_url: &started.authorize_url,
    };
    let page = reopen(&state, &headers, &query, &dialog, "", name, Some(step)).await;
    with_response_cookie(page, handle_cookie)
}

pub(in crate::routes) async fn complete_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CompleteSubmission>,
) -> Response {
    let target = target(&form.credential_id, form.expected_revocation_generation);
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    let Some((dialog, reconnect)) = target.filter(|_| valid_credential_name(name)) else {
        let error = "credential-invalid";
        return reopen(&state, &headers, &query, NEW_DIALOG, error, name, None).await;
    };
    let clear = clear_claude_sign_in_cookie(&state.public_origin);
    let Some(handle) = claude_sign_in_handle(&headers, &state.public_origin) else {
        let error = "claude-sign-in-expired";
        let page = reopen(&state, &headers, &query, &dialog, error, name, None).await;
        return with_response_cookie(page, clear);
    };
    let Some(code) = credentials_connect::pasted_claude_code(&form.code) else {
        // Nothing is sent, so the handle stays for another paste.
        let step = Some(CodeStep { authorize_url: "" });
        let error = "claude-code-invalid";
        return reopen(&state, &headers, &query, &dialog, error, name, step).await;
    };
    let reconnecting = reconnect.is_some();
    let completed = credentials_connect::complete_claude_sign_in(
        &state,
        cookie,
        name.into(),
        handle.into(),
        code,
        reconnect,
    )
    .await;
    let page = match completed {
        Ok(()) => {
            let message = if reconnecting {
                "claude-sign-in-reconnected"
            } else {
                "claude-sign-in-added"
            };
            page_redirect(message, false, &query, &headers)
        }
        Err(error) => {
            let refusal = match credentials_connect::claude_sign_in_refusal(&error) {
                Some(ClaudeSignInRefusal::CodeRefused) => "claude-code-refused",
                Some(ClaudeSignInRefusal::Expired) => "claude-sign-in-expired",
                None => "",
            };
            if refusal.is_empty() {
                addition_error(&state, &headers, &query, &dialog, name, error.code).await
            } else {
                reopen(&state, &headers, &query, &dialog, refusal, name, None).await
            }
        }
    };
    with_response_cookie(page, clear)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The sign-in's own dialogs: a new sign-in, and a sign-in row's Reconnect.
pub(super) fn approved_dialog(requested: &str, data: &CredentialSettingsData) -> bool {
    requested == NEW_DIALOG
        || data.credentials.iter().any(|credential| {
            credential.claude_sign_in
                && requested == row_action_dialog("credential", &credential.id, "reconnect")
        })
}

pub(super) fn approved_message(code: &str) -> &'static str {
    match code {
        "claude-sign-in-added" => "Claude connected.",
        "claude-sign-in-reconnected" => "Claude reconnected.",
        _ => "",
    }
}

pub(super) fn approved_error(code: &str) -> &'static str {
    match code {
        "claude-code-invalid" => {
            "That isn't the code Claude shows; copy the whole code and paste it again."
        }
        "claude-code-refused" => "Claude didn't accept that code; start again.",
        "claude-sign-in-expired" => "This sign-in ended after 15 minutes; start again.",
        _ => "",
    }
}

#[cfg(test)]
mod tests;
