use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use codewire_proto::codewire::console::v1::{AddCreditOutcome, AddCreditRefusal};
use connectrpc::ErrorCode;
use serde::Deserialize;

use crate::{
    billing_banner::{BannerViewer, SandboxLoad, billing_banner},
    billing_connect, environment_connect,
    response::{login_redirect, redirect, render_billing_page, render_template},
    routes::organization_governance::{
        action_context, connect_page_error, get_context, get_context_without_rail,
        mutation_redirect,
    },
    security::{csrf_cookie, new_csrf_token, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::{BillingBannerTemplate, OrganizationBillingTemplate},
};

/// How long the banner waits for the organization's Sandboxes.
const BANNER_SANDBOXES_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Default, Deserialize)]
pub(super) struct BillingQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    /// The credit a message is about, in cents.
    #[serde(default)]
    amount: String,
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

#[derive(Debug, Deserialize)]
pub(super) struct AddCreditSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    /// The page's attempt key, so a resubmitted form never charges twice.
    request: String,
    /// A chip's euros ("100"), or "custom".
    #[serde(default)]
    choice: String,
    /// The custom amount in euros, used only when the choice is "custom".
    #[serde(default)]
    amount: String,
}

/// The amounts the chips offer, in euros (owner, 2026-11-11, #3381).
const CREDIT_CHIPS: [i32; 4] = [50, 100, 250, 500];

/// The chosen amount in cents: a chip, or a custom amount from EUR 5 to
/// EUR 1,000 with at most two decimals.
fn credit_cents(choice: &str, amount: &str) -> Option<i32> {
    if choice == "custom" {
        return billing_connect::top_up_cents(amount);
    }
    CREDIT_CHIPS
        .iter()
        .find(|euros| euros.to_string() == choice)
        .map(|euros| euros * 100)
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
        billing_message(&query.message, &query.amount),
        billing_error(&query.error).to_owned(),
    )
    .await
    {
        Ok(billing) => billing,
        Err(error) => return connect_page_error(error, &continuation, &headers),
    };
    with_csrf_cookie(
        render_billing_page(OrganizationBillingTemplate {
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

/// Buys a one-time amount of credit (#3381): back to Billing once the card is
/// charged, or on to Stripe where the bank wants the payment approved or
/// there is no card yet.
pub(super) async fn add_credit(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<AddCreditSubmission>,
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
    let Some(amount_cents) = credit_cents(&submission.choice, &submission.amount) else {
        return mutation_redirect(&state, path, "", "invalid-credit", &headers);
    };
    let return_url = format!("{}{}", state.public_origin, organization.billing_url);
    let result = billing_connect::add_credit(
        &state,
        cookie,
        organization.id,
        amount_cents,
        submission.request,
        &return_url,
    )
    .await;
    let response = match result {
        Ok(response) => response,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(&path, &headers);
        }
        Err(error) => return mutation_redirect(&state, path, "", mutation_error(&error), &headers),
    };
    match response.outcome.as_known() {
        Some(AddCreditOutcome::Paid) => with_csrf_cookie(
            redirect(
                format!("{path}?message=credit-added&amount={amount_cents}"),
                &headers,
            ),
            csrf_cookie(&state.public_origin, &new_csrf_token()),
        ),
        Some(AddCreditOutcome::ActionRequired) => {
            let url = billing_connect::safe_stripe_url(response.payment_url);
            if url.is_empty() {
                mutation_redirect(&state, path, "", "invalid-redirect", &headers)
            } else {
                redirect(url, &headers)
            }
        }
        Some(AddCreditOutcome::Refused) => {
            let error = match response.refusal.as_known() {
                Some(AddCreditRefusal::InProgress) => "credit-in-progress",
                _ => credit_decline(&response.decline_code),
            };
            mutation_redirect(&state, path, "", error, &headers)
        }
        _ => mutation_redirect(&state, path, "", "unavailable", &headers),
    }
}

/// The page's error code for a declined card.
fn credit_decline(code: &str) -> &'static str {
    match code {
        "insufficient_funds" => "credit-insufficient-funds",
        "expired_card" => "credit-expired-card",
        _ => "credit-declined",
    }
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

/// The page's confirmation for a message code. The credit messages name the
/// amount, read as a number of cents and written as euros.
fn billing_message(value: &str, amount: &str) -> String {
    let euros = amount
        .parse::<i32>()
        .ok()
        .filter(|cents| (500..=100_000).contains(cents))
        .map(|cents| format!("€{}", billing_connect::top_up_euros(cents)));
    match (value, euros) {
        ("payment-updated", _) => "Payment details updated.".to_owned(),
        ("top-up-saved", _) => "Automatic top-up saved.".to_owned(),
        ("credit-added", Some(euros)) => format!("{euros} added to your credit."),
        ("credit-added", None) => "Credit added.".to_owned(),
        ("credit-paid", Some(euros)) => {
            format!("Payment received. {euros} is added to your credit in a moment.")
        }
        ("credit-paid", None) => "Payment received. Your credit updates in a moment.".to_owned(),
        _ => String::new(),
    }
}

/// The billing banner, loaded after an organization page has rendered so it
/// never holds the page up. It answers with one `.cw-banner`, or with an
/// empty body that removes the placeholder, whenever there is nothing to say
/// or anything it needs is unavailable.
pub(super) async fn banner_fragment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    let banner = match get_context_without_rail(&state, &headers, &slug, &billing_path(&slug)).await
    {
        Ok((_, organization, cookie)) => {
            match billing_connect::credit_facts(&state, cookie.clone(), &organization.id).await {
                Some(facts) => {
                    // Only a banner that may show reads the Sandboxes.
                    let sandboxes = if facts.banner_needs_sandboxes() {
                        tokio::time::timeout(
                            BANNER_SANDBOXES_TIMEOUT,
                            environment_connect::environments(
                                &state,
                                cookie,
                                &organization.id,
                                false,
                            ),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .map(|rows| rows.iter().map(SandboxLoad::from).collect::<Vec<_>>())
                    } else {
                        None
                    };
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_secs() as i64);
                    billing_banner(
                        &facts,
                        sandboxes.as_deref(),
                        &BannerViewer {
                            can_admin: organization.can_admin,
                            billing_url: &organization.billing_url,
                        },
                        now,
                    )
                }
                None => None,
            }
        }
        // The page itself answers for its session and organization.
        Err(_) => None,
    };
    render_template(StatusCode::OK, BillingBannerTemplate { banner })
}

fn billing_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to manage organization billing.",
        "invalid" => "The billing request was invalid.",
        "not-found" => "Billing details were not found for this organization.",
        "invalid-redirect" => "The billing provider returned an unsafe destination.",
        "invalid-top-up" => "Enter a top-up amount from €5 to €1,000, with at most two decimals.",
        "invalid-credit" => {
            "Choose an amount, or enter one from €5 to €1,000 with at most two decimals."
        }
        "credit-in-progress" => {
            "A payment for this organization's credit is already being processed. Try again in a minute."
        }
        "credit-declined" => {
            "Your card was declined, so no credit was added. Update your payment method in Stripe, or try again."
        }
        "credit-insufficient-funds" => {
            "Your card was declined for insufficient funds, so no credit was added."
        }
        "credit-expired-card" => {
            "Your card has expired, so no credit was added. Update your payment method in Stripe."
        }
        "credit-cancelled" => "Payment cancelled. No credit was added.",
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
            billing_message("payment-updated", ""),
            "Payment details updated."
        );
        assert_eq!(billing_message("<script>", "10000"), "");
        assert_eq!(
            billing_message("top-up-saved", ""),
            "Automatic top-up saved."
        );
        assert_eq!(
            billing_error("invalid-redirect"),
            "The billing provider returned an unsafe destination."
        );
        assert_eq!(billing_error("raw-upstream-detail"), "");
    }

    #[test]
    fn credit_messages_name_the_amount_only_when_it_is_one() {
        assert_eq!(
            billing_message("credit-added", "10000"),
            "€100 added to your credit."
        );
        assert_eq!(
            billing_message("credit-added", "1250"),
            "€12.50 added to your credit."
        );
        assert_eq!(
            billing_message("credit-paid", "25000"),
            "Payment received. €250 is added to your credit in a moment."
        );
        // A missing, malformed or out-of-range amount is never echoed.
        for amount in ["", "<b>1</b>", "499", "100001", "-500", "1e4"] {
            assert_eq!(billing_message("credit-added", amount), "Credit added.");
            assert_eq!(
                billing_message("credit-paid", amount),
                "Payment received. Your credit updates in a moment."
            );
        }
        assert_eq!(
            billing_error("credit-cancelled"),
            "Payment cancelled. No credit was added."
        );
    }

    #[test]
    fn a_credit_choice_is_a_chip_or_a_custom_amount() {
        assert_eq!(credit_cents("50", ""), Some(5_000));
        assert_eq!(credit_cents("100", "7"), Some(10_000));
        assert_eq!(credit_cents("250", ""), Some(25_000));
        assert_eq!(credit_cents("500", ""), Some(50_000));
        assert_eq!(credit_cents("custom", "12.50"), Some(1_250));
        assert_eq!(credit_cents("custom", "1000"), Some(100_000));
        for (choice, amount) in [
            ("", ""),
            ("75", ""),
            ("custom", ""),
            ("custom", "4.99"),
            ("custom", "1000.01"),
            ("custom", "12.345"),
            ("5000", ""),
        ] {
            assert_eq!(credit_cents(choice, amount), None, "{choice:?} {amount:?}");
        }
    }

    #[test]
    fn a_declined_card_gets_its_own_message() {
        assert_eq!(
            credit_decline("insufficient_funds"),
            "credit-insufficient-funds"
        );
        assert_eq!(credit_decline("expired_card"), "credit-expired-card");
        for code in ["card_declined", "authentication_required", "", "other"] {
            assert_eq!(credit_decline(code), "credit-declined");
        }
        for code in [
            "credit-insufficient-funds",
            "credit-expired-card",
            "credit-declined",
            "credit-in-progress",
            "invalid-credit",
        ] {
            assert!(!billing_error(code).is_empty(), "{code}");
        }
    }
}

#[cfg(test)]
#[path = "billing_banner_tests.rs"]
mod billing_banner_tests;
