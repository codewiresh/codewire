//! The admin organization page's credit adjustment (#4754).

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use super::admin::{
    AdminQuery, admin_action_page_context_for, admin_redirect_to, organization_path,
    quota_response, valid_organization_id,
};
use crate::{
    admin_connect::{self, CreditConfirmationView},
    error::WebError,
    response::{error_page, render_page},
    security::{csrf_cookie, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::AdminOrganizationTemplate,
    view::{DashboardView, connect_error_reason},
};

#[derive(Debug, Deserialize)]
pub(super) struct CreditSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    organization_id: String,
    /// Euros, signed, at most two decimals.
    amount: String,
    reason: String,
    idempotency_key: String,
    /// The balance the administrator was shown and confirmed, in nano-euros,
    /// for an adjustment that leaves it below zero (#4754).
    #[serde(default)]
    confirmed_balance: String,
}

pub(super) async fn adjust_organization_credit(
    State(state): State<AppState>,
    Query(query): Query<AdminQuery>,
    headers: HeaderMap,
    Form(submission): Form<CreditSubmission>,
) -> Response {
    if !valid_organization_id(&submission.organization_id) {
        return error_page(WebError::NotFound);
    }
    let path = organization_path(&submission.organization_id);
    let (dashboard, cookie) =
        match admin_action_page_context_for(&state, &headers, &submission.csrf, &query.org, &path)
            .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    let reason = submission.reason.trim();
    let Some(amount_nano_eur) = admin_connect::euro_amount_nano(&submission.amount) else {
        return admin_redirect_to(&path, "", "invalid-credit", &headers);
    };
    if reason.is_empty()
        || reason.chars().count() > 500
        || !valid_organization_id(&submission.idempotency_key)
    {
        return admin_redirect_to(&path, "", "invalid-credit", &headers);
    }
    let confirmed = match submission.confirmed_balance.as_str() {
        "" => None,
        value => match value.parse::<i64>() {
            Ok(balance) => Some(balance),
            Err(_) => return admin_redirect_to(&path, "", "invalid-credit", &headers),
        },
    };
    let result = admin_connect::adjust_organization_credit(
        &state,
        cookie.clone(),
        &submission.organization_id,
        amount_nano_eur,
        reason,
        &submission.idempotency_key,
        confirmed,
    )
    .await;
    match result {
        // It would leave the balance below zero, and that balance was not
        // the one confirmed: ask, with the balance as it is now.
        Err(error) if asks_to_confirm_balance(&error) => {
            ask(
                &state,
                &headers,
                &dashboard,
                cookie,
                &submission,
                amount_nano_eur,
            )
            .await
        }
        result => quota_response(result, &path, "credit-adjusted", &headers),
    }
}

/// Whether a refusal asks the administrator to confirm the balance:
/// orchestration's `negative_balance_unconfirmed` (`connect_error.rs`).
/// Every other refusal says why on the page instead.
fn asks_to_confirm_balance(error: &ConnectError) -> bool {
    error.code == ErrorCode::FailedPrecondition
        && connect_error_reason(error).as_deref() == Some("NEGATIVE_BALANCE_UNCONFIRMED")
}

/// The organization page again, asking whether to apply an adjustment that
/// leaves the balance below zero, and saying what that sets off.
async fn ask(
    state: &AppState,
    headers: &HeaderMap,
    dashboard: &DashboardView,
    cookie: HeaderValue,
    submission: &CreditSubmission,
    amount_nano_eur: i64,
) -> Response {
    let path = organization_path(&submission.organization_id);
    let (organization, card) = tokio::join!(
        admin_connect::organization(state, cookie.clone(), &submission.organization_id),
        admin_connect::default_card(state, cookie, &submission.organization_id),
    );
    let organization = match organization {
        Ok(organization) => organization,
        Err(error) => return quota_response(Err(error), &path, "", headers),
    };
    let balance = organization
        .credit_balance_nano_eur
        .saturating_add(amount_nano_eur);
    let confirmation = CreditConfirmationView {
        amount: submission.amount.trim().to_owned(),
        reason: submission.reason.trim().to_owned(),
        idempotency_key: submission.idempotency_key.clone(),
        confirmed_balance_nano_eur: balance,
        question: admin_connect::negative_balance_question(
            balance,
            organization.auto_top_up_enabled,
            organization.auto_top_up_cents,
            card.as_ref().map(Option::as_deref),
        ),
    };
    let token = page_csrf_token(headers);
    with_csrf_cookie(
        render_page(AdminOrganizationTemplate {
            view: dashboard,
            organization: &organization,
            csrf_token: &token,
            credit_key: &submission.idempotency_key,
            credit_confirmation: Some(&confirmation),
            message: "",
            error: "",
        }),
        csrf_cookie(&state.public_origin, &token),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(reason: &str) -> ConnectError {
        let info = codewire_proto::google::rpc::ErrorInfo {
            reason: reason.to_owned(),
            domain: "codewire.sh".to_owned(),
            ..Default::default()
        };
        ConnectError::failed_precondition("refused").with_detail(
            connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &info),
        )
    }

    #[test]
    fn only_an_unconfirmed_negative_balance_asks() {
        assert!(asks_to_confirm_balance(&refusal(
            "NEGATIVE_BALANCE_UNCONFIRMED"
        )));
        assert!(!asks_to_confirm_balance(&refusal("INVALID_STATE")));
        assert!(!asks_to_confirm_balance(
            &ConnectError::failed_precondition("no reason")
        ));
    }
}
