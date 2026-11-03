use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use connectrpc::ErrorCode;
use serde::Deserialize;

use crate::{
    billing_connect,
    response::{login_redirect, redirect, render_page},
    routes::organization_governance::{
        action_context, connect_page_error, get_context, mutation_redirect,
    },
    security::{csrf_cookie, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::OrganizationBillingTemplate,
};

#[derive(Debug, Default, Deserialize)]
pub(super) struct BillingQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BillingSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct AutoTopUpSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    /// Present only when the box is checked.
    #[serde(default)]
    enabled: Option<String>,
    /// Euros, at most two decimals.
    amount: String,
}

pub(super) async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<BillingQuery>,
    headers: HeaderMap,
) -> Response {
    let continuation = billing_path(&slug);
    let (dashboard, organization, cookie) =
        match get_context(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let token = page_csrf_token(&headers);
    let billing = match billing_connect::billing_page(
        &state,
        cookie,
        &organization.id,
        organization.can_admin,
        token.clone(),
        billing_message(&query.message).to_owned(),
        billing_error(&query.error).to_owned(),
    )
    .await
    {
        Ok(billing) => billing,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    with_csrf_cookie(
        render_page(OrganizationBillingTemplate {
            view: &dashboard,
            organization: &organization,
            billing: &billing,
            active_tab: "billing",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

pub(super) async fn portal(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<BillingSubmission>,
) -> Response {
    billing_session(&state, &slug, &headers, &submission.csrf, true).await
}

pub(super) async fn setup(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<BillingSubmission>,
) -> Response {
    billing_session(&state, &slug, &headers, &submission.csrf, false).await
}

/// Turns automatic top-up on or off and sets its amount (#3381).
pub(super) async fn auto_top_up(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<AutoTopUpSubmission>,
) -> Response {
    let path = billing_path(&slug);
    let (_, organization, cookie) =
        match action_context(&state, &headers, &slug, &submission.csrf, path.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !organization.can_admin {
        return mutation_redirect(&state, path, "", "not-authorized", &headers);
    }
    let Some(amount_cents) = billing_connect::top_up_cents(&submission.amount) else {
        return mutation_redirect(&state, path, "", "invalid-top-up", &headers);
    };
    let enabled = submission.enabled.as_deref() == Some("true");
    match billing_connect::update_auto_top_up(
        &state,
        cookie,
        organization.id,
        enabled,
        amount_cents,
    )
    .await
    {
        Ok(()) => mutation_redirect(&state, path, "top-up-saved", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&path, &headers),
        Err(error) => mutation_redirect(&state, path, "", mutation_error(&error), &headers),
    }
}

async fn billing_session(
    state: &AppState,
    slug: &str,
    headers: &HeaderMap,
    csrf: &str,
    portal: bool,
) -> Response {
    let path = billing_path(slug);
    let (_, organization, cookie) =
        match action_context(state, headers, slug, csrf, path.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !organization.can_admin {
        return mutation_redirect(state, path, "", "not-authorized", headers);
    }
    let return_url = format!("{}{}", state.public_origin, organization.billing_url);
    let result = if portal {
        billing_connect::create_portal_session(state, cookie, organization.id, return_url).await
    } else {
        billing_connect::create_setup_session(state, cookie, organization.id, return_url).await
    };
    match result {
        Ok(raw_url) => {
            let url = billing_connect::safe_stripe_url(raw_url);
            if url.is_empty() {
                mutation_redirect(state, path, "", "invalid-redirect", headers)
            } else {
                redirect(url, headers)
            }
        }
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&path, headers),
        Err(error) => mutation_redirect(state, path, "", mutation_error(&error), headers),
    }
}

fn billing_path(slug: &str) -> String {
    format!("/{slug}/billing/")
}

fn billing_message(value: &str) -> &'static str {
    match value {
        "payment-updated" => "Payment details updated.",
        "top-up-saved" => "Automatic top-up saved.",
        _ => "",
    }
}

fn billing_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to manage organization billing.",
        "invalid" => "The billing request was invalid.",
        "not-found" => "Billing details were not found for this organization.",
        "invalid-redirect" => "The billing provider returned an unsafe destination.",
        "invalid-top-up" => "Enter a top-up amount from €5 to €1,000, with at most two decimals.",
        "unavailable" => "The billing service is temporarily unavailable.",
        _ => "",
    }
}

fn mutation_error(error: &connectrpc::ConnectError) -> &'static str {
    match error.code {
        ErrorCode::PermissionDenied => "not-authorized",
        ErrorCode::InvalidArgument => "invalid",
        ErrorCode::NotFound => "not-found",
        _ => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_feedback_is_allowlisted() {
        assert_eq!(
            billing_message("payment-updated"),
            "Payment details updated."
        );
        assert_eq!(billing_message("<script>"), "");
        assert_eq!(billing_message("top-up-saved"), "Automatic top-up saved.");
        assert_eq!(
            billing_error("invalid-redirect"),
            "The billing provider returned an unsafe destination."
        );
        assert_eq!(billing_error("raw-upstream-detail"), "");
    }
}
