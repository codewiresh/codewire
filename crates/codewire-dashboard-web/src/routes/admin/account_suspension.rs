//! Suspend and Unsuspend on Account Access (#3297, #4579). Each is confirmed
//! in a dialog on the page and calls the administrator API, which suspends
//! the account and the organizations it alone owns in one step, or clears
//! that suspension.

use axum::{
    Form,
    extract::{Query, State},
    http::HeaderMap,
    response::Response,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use super::{
    ACCOUNTS_PATH, AdminQuery, account_redirect, admin_action_page_context_for, valid_identifier,
};
use crate::{
    admin_connect,
    error::WebError,
    response::{error_page, login_redirect},
    state::AppState,
};

/// The longest reason the administrator API records.
const MAX_REASON_CHARS: usize = 2_000;

#[derive(Debug, Deserialize)]
pub(in crate::routes) struct SuspendSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    user_id: String,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::routes) struct UnsuspendSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    user_id: String,
}

/// The confirmation's "Suspend account".
pub(in crate::routes) async fn suspend_account(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<SuspendSubmission>,
) -> Response {
    let (dashboard, cookie) = match admin_action_page_context_for(
        &state,
        &headers,
        &submission.csrf,
        &query.org,
        ACCOUNTS_PATH,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.user_id) {
        return account_redirect("", "not-found", &headers);
    }
    if submission.user_id == dashboard.account_id {
        return account_redirect("", "suspend-own", &headers);
    }
    let Some(reason) = valid_reason(&submission.reason) else {
        return account_redirect("", "suspend-reason", &headers);
    };
    match admin_connect::suspend_account(&state, cookie, submission.user_id, reason).await {
        Ok(0) => account_redirect("account-suspended", "", &headers),
        Ok(_) => account_redirect("account-suspended-shared", "", &headers),
        Err(error) => refused(&error, &headers),
    }
}

/// The confirmation's "Unsuspend account".
pub(in crate::routes) async fn unsuspend_account(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<UnsuspendSubmission>,
) -> Response {
    let cookie = match admin_action_page_context_for(
        &state,
        &headers,
        &submission.csrf,
        &query.org,
        ACCOUNTS_PATH,
    )
    .await
    {
        Ok((_, cookie)) => cookie,
        Err(response) => return response,
    };
    if !valid_identifier(&submission.user_id) {
        return account_redirect("", "not-found", &headers);
    }
    match admin_connect::unsuspend_account(&state, cookie, submission.user_id).await {
        Ok(()) => account_redirect("account-unsuspended", "", &headers),
        Err(error) => refused(&error, &headers),
    }
}

/// The reason as the API records it: trimmed, and 1 to 2,000 characters.
fn valid_reason(reason: &str) -> Option<String> {
    let reason = reason.trim();
    (!reason.is_empty() && reason.chars().count() <= MAX_REASON_CHARS).then(|| reason.to_owned())
}

/// Where a refused suspend or unsuspend goes. A conflict means the account
/// was suspended or unsuspended meanwhile, or is being deleted.
fn refused(error: &ConnectError, headers: &HeaderMap) -> Response {
    match error.code {
        ErrorCode::Unauthenticated => login_redirect(ACCOUNTS_PATH, headers),
        ErrorCode::PermissionDenied => error_page(WebError::Forbidden),
        ErrorCode::NotFound => account_redirect("", "not-found", headers),
        ErrorCode::InvalidArgument => account_redirect("", "suspend-reason", headers),
        ErrorCode::AlreadyExists | ErrorCode::FailedPrecondition | ErrorCode::Aborted => {
            account_redirect("", "suspension-changed", headers)
        }
        _ => account_redirect("", "unavailable", headers),
    }
}

/// The notice after a suspension changed.
pub(super) fn message(value: &str) -> &'static str {
    match value {
        "account-suspended" => {
            "Account suspended. It's signed out everywhere and its API keys are disabled. Sandboxes in the organizations it alone owns, and any it created elsewhere, stop."
        }
        "account-suspended-shared" => {
            "Account suspended. It's signed out everywhere and its API keys are disabled. Sandboxes in the organizations it alone owns, and any it created elsewhere, stop. Organizations it owns with someone else are left to that owner."
        }
        "account-unsuspended" => {
            "Account unsuspended. It can sign in again. Its Sandboxes stay stopped and its API keys stay disabled."
        }
        _ => "",
    }
}

/// The error after a suspension was refused.
pub(super) fn error(value: &str) -> &'static str {
    match value {
        "suspended" => "That account is suspended. Unsuspend it instead.",
        "suspend-own" => "You can't suspend your own account.",
        "suspend-reason" => "Say why you're suspending the account, in at most 2,000 characters.",
        "suspension-changed" => {
            "That account was suspended or unsuspended meanwhile, or is being deleted. The list shows it as it is now."
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn a_reason_is_trimmed_and_between_one_and_two_thousand_characters() {
        assert_eq!(valid_reason("  mining  ").as_deref(), Some("mining"));
        assert_eq!(valid_reason(" \n "), None);
        assert_eq!(valid_reason(""), None);
        let longest = "é".repeat(MAX_REASON_CHARS);
        assert_eq!(valid_reason(&longest), Some(longest.clone()));
        assert_eq!(valid_reason(&format!("{longest}x")), None);
    }

    #[test]
    fn a_refusal_says_why_on_the_page() {
        let location = |code| {
            let response = refused(&ConnectError::new(code, "refused"), &HeaderMap::new());
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(
            location(ErrorCode::AlreadyExists).as_deref(),
            Some("/admin/accounts/?error=suspension-changed")
        );
        assert_eq!(
            location(ErrorCode::FailedPrecondition).as_deref(),
            Some("/admin/accounts/?error=suspension-changed")
        );
        assert_eq!(
            location(ErrorCode::InvalidArgument).as_deref(),
            Some("/admin/accounts/?error=suspend-reason")
        );
        assert_eq!(
            location(ErrorCode::NotFound).as_deref(),
            Some("/admin/accounts/?error=not-found")
        );
        for code in [
            "suspended",
            "suspend-own",
            "suspend-reason",
            "suspension-changed",
        ] {
            assert!(!error(code).is_empty(), "{code}");
        }
        for code in [
            "account-suspended",
            "account-suspended-shared",
            "account-unsuspended",
        ] {
            assert!(!message(code).is_empty(), "{code}");
        }
    }
}
