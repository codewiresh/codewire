//! `/admin/accounts/{user_id}/delete`: an admin sees what deleting someone
//! else's account does, then confirms it with the account's address, their
//! own password and a fresh second factor (#4541). The IdP checks all of it
//! again; this page only explains its answer.

use axum::{
    Form,
    extract::{Path, Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::{ACCOUNTS_PATH, AdminQuery, account_redirect, admin_context};
use crate::{
    account_sessions::valid_id,
    account_two_factor::browser_user_agent,
    admin_account_deletion::{Confirmation, Refusal, Stage, delete_account, log_refused},
    error::WebError,
    raw_auth::{append_session_cookies, get_json},
    response::{error_page, login_redirect, redirect, render_template},
    routes::settings::{count, exact_pattern},
    security::{
        csrf_cookie, new_csrf_token, page_csrf_token, request_has_same_origin, valid_csrf_token,
        with_csrf_cookie,
    },
    state::AppState,
    templates::AdminAccountDeleteTemplate,
    view::{AdminAccountDeletionView, DashboardView, DeletedOrganizationView},
};

/// An admin deletes their own account from Settings.
const SETTINGS_DELETE_PATH: &str = "/settings/delete-account/";

/// The IdP's `GET /api/admin/accounts/{user_id}/deletion-plan`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeletionPlanResponse {
    email: String,
    is_admin: bool,
    personal_organizations: Vec<PersonalOrganization>,
    shared_organizations: Vec<String>,
    blocking_organizations: Vec<String>,
    deletion_running: bool,
}

#[derive(Deserialize)]
struct PersonalOrganization {
    name: String,
    sandboxes: i64,
}

// No Debug: the password and code are secrets, the CSRF field is authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::routes) struct DeleteSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    user_id: String,
    confirm_email: String,
    password: String,
    proof: String,
}

fn page_path(user_id: &str) -> String {
    format!("{ACCOUNTS_PATH}{user_id}/delete")
}

/// The confirmation page.
pub(in crate::routes) async fn page(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_id(&user_id) {
        return error_page(WebError::NotFound);
    }
    let continuation = page_path(&user_id);
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if dashboard.account_id == user_id {
        return redirect(SETTINGS_DELETE_PATH.to_owned(), &headers);
    }
    render(&state, &headers, &dashboard, cookie, &user_id, None).await
}

/// "Delete account": start the deletion, or show the page again saying why
/// it did not start.
pub(in crate::routes) async fn delete(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    form: Result<Form<DeleteSubmission>, FormRejection>,
) -> Response {
    // Every refusal here leaves a log line with a fixed reason (#5770);
    // delete_account logs its own and the IdP's.
    let Ok(Form(form)) = form else {
        log_refused(Stage::Dashboard, "form_rejected", None);
        return error_page(WebError::Forbidden);
    };
    if !request_has_same_origin(&headers, &state.public_origin)
        || !valid_csrf_token(&headers, &form.csrf)
    {
        log_refused(
            Stage::Dashboard,
            "origin_or_csrf",
            valid_id(&form.user_id).then_some(form.user_id.as_str()),
        );
        return error_page(WebError::CsrfRejected);
    }
    if !valid_id(&form.user_id) {
        log_refused(Stage::Dashboard, "invalid_account_id", None);
        return account_redirect("", "not-found", &headers);
    }
    let continuation = page_path(&form.user_id);
    let (dashboard, cookie) = match admin_context(&state, &headers, &continuation, &query.org).await
    {
        Ok(context) => context,
        Err(response) => {
            log_refused(Stage::Dashboard, "no_admin_session", Some(&form.user_id));
            return response;
        }
    };
    if dashboard.account_id == form.user_id {
        log_refused(Stage::Dashboard, "own_account", Some(&form.user_id));
        return redirect(SETTINGS_DELETE_PATH.to_owned(), &headers);
    }
    let confirmation = Confirmation {
        email: &form.confirm_email,
        password: &form.password,
        proof: &form.proof,
    };
    let result = delete_account(
        &state,
        cookie.clone(),
        browser_user_agent(&headers),
        &form.user_id,
        &confirmation,
    )
    .await;
    match result {
        Ok(()) => deletion_started(&form.user_id, &headers),
        Err(Refusal::Unauthorized) => login_redirect(ACCOUNTS_PATH, &headers),
        Err(Refusal::Forbidden) => error_page(WebError::Forbidden),
        Err(Refusal::NotFound) => account_redirect("", "not-found", &headers),
        Err(refusal) => {
            let failed = Failed {
                refusal,
                confirm_email: form.confirm_email.trim(),
            };
            render(
                &state,
                &headers,
                &dashboard,
                cookie,
                &form.user_id,
                Some(failed),
            )
            .await
        }
    }
}

/// A refused deletion, and the address the admin typed.
struct Failed<'a> {
    refusal: Refusal,
    confirm_email: &'a str,
}

fn deletion_started(user_id: &str, headers: &HeaderMap) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("message", "deletion-started")
        .append_pair("deleted", user_id)
        .finish();
    redirect(format!("{ACCOUNTS_PATH}?{query}"), headers)
}

/// The page from a fresh plan, so a refusal is explained by what is true
/// now: the account became an admin, or an organization is in the way.
async fn render(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: &DashboardView,
    cookie: HeaderValue,
    user_id: &str,
    failed: Option<Failed<'_>>,
) -> Response {
    let path = format!("/api/admin/accounts/{user_id}/deletion-plan");
    let identity = match get_json::<DeletionPlanResponse>(state, &path, cookie).await {
        Ok(identity) => identity,
        Err(()) => return error_page(WebError::IdentityUnavailable),
    };
    match identity.status {
        status if status.is_success() => {}
        StatusCode::UNAUTHORIZED => return login_redirect(&page_path(user_id), headers),
        StatusCode::FORBIDDEN => return error_page(WebError::Forbidden),
        StatusCode::NOT_FOUND => return account_redirect("", "not-found", headers),
        _ => return error_page(WebError::IdentityUnavailable),
    }
    let Some(plan) = identity.body.as_ref() else {
        return error_page(WebError::IdentityUnavailable);
    };
    // A session the IdP changed gets a new token, and the form renders with
    // the token the browser keeps.
    let token = if identity.changes_session() {
        new_csrf_token()
    } else {
        page_csrf_token(headers)
    };
    let (error, confirm_email) = match &failed {
        Some(failed) => (
            error_message(&failed.refusal, plan),
            failed.confirm_email.to_owned(),
        ),
        None => (String::new(), String::new()),
    };
    let page = deletion_view(user_id, plan, token, error, confirm_email);
    let response = with_csrf_cookie(
        render_template(
            StatusCode::OK,
            AdminAccountDeleteTemplate {
                view: dashboard,
                page: &page,
            },
        ),
        csrf_cookie(&state.public_origin, &page.csrf_token),
    );
    append_session_cookies(response, &identity)
}

fn deletion_view(
    user_id: &str,
    plan: &DeletionPlanResponse,
    csrf_token: String,
    error: String,
    confirm_email: String,
) -> AdminAccountDeletionView {
    AdminAccountDeletionView {
        user_id: user_id.to_owned(),
        email_pattern: exact_pattern(&plan.email),
        email: plan.email.clone(),
        confirm_email,
        csrf_token,
        personal: plan
            .personal_organizations
            .iter()
            .map(|organization| DeletedOrganizationView {
                name: organization.name.clone(),
                detail: count(organization.sandboxes, "sandbox", "sandboxes") + " deleted with it",
            })
            .collect(),
        shared: plan.shared_organizations.clone(),
        blocking: plan.blocking_organizations.clone(),
        is_admin: plan.is_admin,
        deletion_running: plan.deletion_running,
        error,
    }
}

/// One plain sentence per refusal. The IdP refuses the address, an admin and
/// a blocking organization alike, so the fresh plan says which it was, in the
/// order the IdP checks them.
fn error_message(refusal: &Refusal, plan: &DeletionPlanResponse) -> String {
    match refusal {
        Refusal::ProofRejected => {
            "Your password or code is incorrect. Nothing was deleted.".to_owned()
        }
        Refusal::Locked => {
            "Your account is locked after too many failed attempts. Try again later. Nothing was deleted."
                .to_owned()
        }
        Refusal::RateLimited(detail) => {
            format!("You've reached the limit: {detail}. Nothing was deleted.")
        }
        Refusal::Refused if plan.is_admin => {
            "This account is an admin. Demote them before deleting their account.".to_owned()
        }
        Refusal::Refused if !plan.blocking_organizations.is_empty() => {
            "This account is the only owner of organizations with other members. Transfer or delete them first."
                .to_owned()
        }
        Refusal::Refused => {
            "The address you typed is not this account's. Nothing was deleted.".to_owned()
        }
        // A lost answer may have started the deletion; the page then says so.
        Refusal::Unavailable if plan.deletion_running => String::new(),
        Refusal::Unavailable
        | Refusal::Unauthorized
        | Refusal::Forbidden
        | Refusal::NotFound => "The account could not be deleted. Try again.".to_owned(),
    }
}

#[cfg(test)]
mod tests;
