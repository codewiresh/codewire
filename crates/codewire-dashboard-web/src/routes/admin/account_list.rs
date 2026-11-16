//! `/admin/accounts/`: who may sign in, and with `?account=<id>` the one
//! account an admin page links to, such as a feedback row's sender (#4061).

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use super::{
    ACCOUNTS_PATH, AccountAccessListResponse, AdminQuery, account_access_view, account_error,
    account_message, admin_context,
};
use crate::{
    error::WebError,
    raw_auth::{append_session_cookies, get_json},
    response::{error_page, login_redirect, render_page},
    security::{csrf_cookie, new_csrf_token, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::AdminAccountsTemplate,
};

pub(in crate::routes) async fn list(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = ACCOUNTS_PATH.to_owned();
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let account = valid_account_id(&query.account).then_some(query.account.as_str());
    let path = match account {
        Some(account) => format!(
            "/api/admin/accounts?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("account", account)
                .finish()
        ),
        None => "/api/admin/accounts".to_owned(),
    };
    let identity = match get_json::<AccountAccessListResponse>(&state, &path, cookie).await {
        Ok(identity) => identity,
        Err(()) => return error_page(WebError::IdentityUnavailable),
    };
    if identity.status == StatusCode::UNAUTHORIZED {
        return login_redirect(&continuation, &headers);
    }
    if identity.status == StatusCode::FORBIDDEN {
        return error_page(WebError::Forbidden);
    }
    if !identity.status.is_success() {
        return error_page(WebError::IdentityUnavailable);
    }
    let Some(body) = identity.body.as_ref() else {
        return error_page(WebError::IdentityUnavailable);
    };
    // An IdP that predates the account filter lists everyone; keep only the
    // one asked for.
    let accounts = body
        .accounts
        .iter()
        .filter(|row| account.is_none_or(|account| row.id == account))
        .map(|row| account_access_view(row, &dashboard.account_id))
        .collect::<Vec<_>>();
    let message = deletion_started(&query, &accounts)
        .unwrap_or_else(|| account_message(&query.message).to_owned());
    // A session the IdP changed gets a new token, and the forms render with
    // the token the browser keeps.
    let token = if identity.changes_session() {
        new_csrf_token()
    } else {
        page_csrf_token(&headers)
    };
    let response = with_csrf_cookie(
        render_page(AdminAccountsTemplate {
            view: &dashboard,
            accounts: &accounts,
            one_account: account.is_some(),
            csrf_token: &token,
            message: &message,
            error: account_error(&query.error),
        }),
        csrf_cookie(&state.public_origin, &token),
    );
    append_session_cookies(response, &identity)
}

/// "Deletion started for <email>" after "Delete account". The URL names the
/// account by id; its address comes from the list, which keeps it while the
/// deletion runs.
fn deletion_started(
    query: &AdminQuery,
    accounts: &[crate::view::AccountAccessView],
) -> Option<String> {
    if query.message != "deletion-started" {
        return None;
    }
    Some(
        match accounts.iter().find(|account| account.id == query.deleted) {
            Some(account) => format!("Deletion started for {}.", account.email),
            None => "Deletion started.".to_owned(),
        },
    )
}

/// Account IDs are short opaque strings of letters, digits, `-` and `_`.
fn valid_account_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_account_ids_shaped_like_the_idps_narrow_the_accounts_list() {
        assert!(valid_account_id("3f9a0c1e5b7d4e2f8a6c0b1d3e5f7a9c"));
        assert!(valid_account_id("user_01-AB"));
        for other in ["", "a b", "a&account=b", "<script>", &"a".repeat(65)] {
            assert!(!valid_account_id(other), "{other}");
        }
    }
}
