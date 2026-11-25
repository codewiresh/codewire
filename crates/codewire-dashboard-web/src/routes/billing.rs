use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Form, Json,
    extract::{Path, Query, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use codewire_proto::codewire::console::v1::{
    AddCreditOutcome, AddCreditRefusal, AddCreditResponse, CardSetupSettlement,
};
use connectrpc::ErrorCode;
use serde::{Deserialize, Serialize};

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
    templates::{BillingBannerTemplate, BillingStackTemplate, OrganizationBillingTemplate},
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

/// A card action: which of the organization's cards.
#[derive(Debug, Deserialize)]
pub(super) struct CardSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    payment_method: String,
}

/// The card form's save: what it chooses beside the card, which billing
/// keeps in the SetupIntent it makes.
#[derive(Debug, Deserialize)]
pub(super) struct CardBeginSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    /// Present only when the switch is on.
    #[serde(default)]
    top_up: Option<String>,
    /// Euros, as the amount control offers them.
    top_up_amount: String,
    /// Present when Add credit with no card yet is buying credit, with its
    /// chip and custom amount.
    #[serde(default)]
    credit: Option<String>,
    #[serde(default)]
    credit_choice: String,
    #[serde(default)]
    credit_amount: String,
}

/// The card form's finish, once Stripe confirmed the card in the page: the
/// SetupIntent and nothing else.
#[derive(Debug, Deserialize)]
pub(super) struct CardFinishSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    setup_intent: String,
}

/// What the card form's script reads back: where to go next, or what to
/// show at the field.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(super) struct CardSetupAnswer {
    #[serde(skip_serializing_if = "String::is_empty")]
    client_secret: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    /// The card is saved but its charge was declined: the dialog stays open
    /// and says so, and Done goes to `location` (#6502).
    #[serde(skip_serializing_if = "String::is_empty")]
    declined: String,
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
    /// The amount typed in Other, in euros; it wins over a chip.
    #[serde(default)]
    amount: String,
}

/// Stripe's return from a bank's redirect names the SetupIntent and its
/// client secret. Nothing here needs the secret, so the page first sends the
/// browser to the same address without it: it stays out of history, and out
/// of any page an error shows instead of Billing (#4750). `None` when the
/// address has no secret.
fn without_client_secret(path: &str, raw_query: Option<&str>) -> Option<String> {
    const SECRET: &str = "setup_intent_client_secret";
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw_query?.as_bytes())
        .into_owned()
        .collect();
    if !pairs.iter().any(|(name, _)| name == SECRET) {
        return None;
    }
    let kept = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().filter(|(name, _)| name != SECRET))
        .finish();
    Some(if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{kept}")
    })
}

/// The amounts the chips offer, in euros (owner, 2026-11-11, #3381).
const CREDIT_CHIPS: [i32; 4] = [50, 100, 250, 500];

/// The chosen amount in cents: an amount typed in Other, from EUR 5 to
/// EUR 1,000 with at most two decimals, wins over a chip.
fn credit_cents(choice: &str, amount: &str) -> Option<i32> {
    if choice == "custom" || !amount.trim().is_empty() {
        return billing_connect::top_up_cents(amount);
    }
    CREDIT_CHIPS
        .iter()
        .find(|euros| euros.to_string() == choice)
        .map(|euros| euros * 100)
}

/// The Billing page. Every answer it gives, an error page or a redirect
/// included, carries the page's referrer policy.
pub(super) async fn page(
    state: State<AppState>,
    slug: Path<String>,
    query: Query<BillingQuery>,
    raw_query: RawQuery,
    headers: HeaderMap,
) -> Response {
    crate::response::with_billing_referrer_policy(
        page_answer(state, slug, query, raw_query, headers).await,
    )
}

async fn page_answer(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<BillingQuery>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let continuation = billing_path(&slug);
    if let Some(clean) = without_client_secret(&continuation, raw_query.as_deref()) {
        return redirect(clean, &headers);
    }
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
        String::new(),
        billing_error(&query.error).to_owned(),
    )
    .await
    {
        Ok(mut billing) => {
            billing.message = billing_message(&query.message, &query.amount, &billing.default_card);
            billing
        }
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

/// The Billing page's live part, re-fetched when its credit changes
/// (`codewire:live:credit`) or the stream resyncs (#4762).
pub(super) async fn stack_fragment(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    let continuation = billing_path(&slug);
    let (_, organization, cookie) =
        match get_context_without_rail(&state, &headers, &slug, &continuation).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let token = page_csrf_token(&headers);
    match billing_connect::billing_page(
        &state,
        cookie,
        &organization.id,
        organization.can_admin,
        token,
        String::new(),
        String::new(),
    )
    .await
    {
        Ok(billing) => render_template(
            StatusCode::OK,
            BillingStackTemplate {
                organization: &organization,
                billing: &billing,
            },
        ),
        Err(error) => connect_page_error(error, &continuation, &headers),
    }
}

/// Starts adding a card once it is saved in the page: billing makes the
/// SetupIntent with the choices, and the script confirms the card with its
/// client secret.
pub(super) async fn begin_card_setup(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<CardBeginSubmission>,
) -> Response {
    let path = billing_path(&slug);
    let (_, organization, cookie) =
        match action_context(&state, &headers, &slug, &submission.csrf, path).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !organization.can_admin {
        return card_answer_error(StatusCode::FORBIDDEN, "not-authorized");
    }
    let Some(top_up_cents) = billing_connect::top_up_cents(&submission.top_up_amount) else {
        return card_answer_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid-top-up");
    };
    let credit_cents = match submission.credit {
        None => None,
        Some(_) => match credit_cents(&submission.credit_choice, &submission.credit_amount) {
            Some(cents) => Some(cents),
            None => return card_answer_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid-credit"),
        },
    };
    let choice = billing_connect::CardSetupChoice {
        auto_top_up_enabled: submission.top_up.as_deref() == Some("true"),
        auto_top_up_cents: top_up_cents,
        credit_cents,
    };
    // The edge's hop of this request, never the browser's chain: billing's
    // per-address cap counts it (#4901).
    let client_hop = codewire_server_core::client_address::forwarded_client_hop(&headers);
    match billing_connect::begin_card_setup(&state, cookie, client_hop, organization.id, choice)
        .await
    {
        Ok(client_secret) => Json(CardSetupAnswer {
            client_secret,
            ..Default::default()
        })
        .into_response(),
        Err(error) if error.code == ErrorCode::NotFound => {
            card_answer_error(StatusCode::SERVICE_UNAVAILABLE, "card-form-off")
        }
        // Billing's card-setup caps (#4874): too many tries in an hour or a
        // day, as card testing would need. The page says so in its own words,
        // as it does every billing error; which window applies is billing's.
        Err(error) if error.code == ErrorCode::ResourceExhausted => {
            card_answer_error(StatusCode::TOO_MANY_REQUESTS, "card-setup-limit")
        }
        Err(error) => card_answer_error(StatusCode::BAD_GATEWAY, mutation_error(&error)),
    }
}

/// Finishes adding a card once Stripe confirmed it in the page: billing
/// makes it the default, buys the credit chosen at Begin, saves the top-up
/// setting chosen there and settles; the page then goes back to Billing
/// saying what happened.
pub(super) async fn finish_card_setup(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<CardFinishSubmission>,
) -> Response {
    let path = billing_path(&slug);
    let (_, organization, cookie) =
        match action_context(&state, &headers, &slug, &submission.csrf, path.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !organization.can_admin {
        return card_answer_error(StatusCode::FORBIDDEN, "not-authorized");
    }
    let done = match billing_connect::finish_card_setup(
        &state,
        cookie,
        organization.id,
        submission.setup_intent,
    )
    .await
    {
        Ok(done) => done,
        Err(error) => {
            return card_answer_error(StatusCode::BAD_GATEWAY, mutation_error(&error));
        }
    };
    Json(CardSetupAnswer {
        location: card_saved_location(&path, &done),
        declined: card_declined(&done).to_owned(),
        ..Default::default()
    })
    .into_response()
}

/// What the dialog says when the card is saved but the charge saving made was
/// declined: the credit chosen with it, or the automatic top-up. Empty when
/// nothing was declined.
fn card_declined(done: &billing_connect::CardSetupDone) -> &'static str {
    if let Some(credit) = &done.credit {
        if credit.outcome.as_known() != Some(AddCreditOutcome::Refused) {
            return "";
        }
        return match credit_decline(&credit.decline_code) {
            "credit-insufficient-funds" => {
                "Your card is saved, but the payment was declined for insufficient funds, so no credit was added. Try another card."
            }
            _ => {
                "Your card is saved, but the payment was declined, so no credit was added. Try another card."
            }
        };
    }
    if matches!(done.settlement, CardSetupSettlement::OutOfCredit) && done.auto_top_up_enabled {
        return "Your card is saved, but its automatic top-up was declined, so no credit was added. Try another card.";
    }
    ""
}

/// Where the page goes once a card is saved: Billing, saying what saving it
/// did. A declined credit purchase says so; the card is saved either way.
fn card_saved_location(path: &str, done: &billing_connect::CardSetupDone) -> String {
    if let Some(credit) = &done.credit {
        return match credit.outcome.as_known() {
            Some(AddCreditOutcome::Paid) => {
                format!(
                    "{path}?message=card-credit-added&amount={}",
                    credit.amount_cents
                )
            }
            // The bank wants the payment approved: Stripe's invoice page,
            // where it is paid, as Add credit with a saved card does.
            Some(AddCreditOutcome::ActionRequired) => {
                let url = billing_connect::safe_stripe_url(credit.payment_url.clone());
                if url.is_empty() {
                    format!("{path}?message=card-saved&error=invalid-redirect")
                } else {
                    url
                }
            }
            _ => format!("{path}?message=card-saved&error={}", credit_refusal(credit)),
        };
    }
    let message = match done.settlement {
        CardSetupSettlement::ToppedUp => "card-topped-up",
        CardSetupSettlement::Pending => "card-top-up-pending",
        CardSetupSettlement::OutOfCredit if done.auto_top_up_enabled => "card-top-up-declined",
        _ => "card-saved",
    };
    format!("{path}?message={message}")
}

/// The page's error code for a purchase that wasn't paid at once.
fn credit_refusal(credit: &AddCreditResponse) -> &'static str {
    match (credit.outcome.as_known(), credit.refusal.as_known()) {
        (_, Some(AddCreditRefusal::InProgress)) => "credit-in-progress",
        (Some(AddCreditOutcome::Refused), _) => credit_decline(&credit.decline_code),
        _ => "unavailable",
    }
}

fn card_answer_error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(CardSetupAnswer {
            error: billing_error(code).to_owned(),
            ..Default::default()
        }),
    )
        .into_response()
}

/// Makes one of the organization's cards the one top-ups charge.
pub(super) async fn make_default_card(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<CardSubmission>,
) -> Response {
    card_action(&state, &slug, &headers, submission, true).await
}

/// Removes one of the organization's cards.
pub(super) async fn remove_card(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(submission): Form<CardSubmission>,
) -> Response {
    card_action(&state, &slug, &headers, submission, false).await
}

async fn card_action(
    state: &AppState,
    slug: &str,
    headers: &HeaderMap,
    submission: CardSubmission,
    make_default: bool,
) -> Response {
    let path = billing_path(slug);
    let (_, organization, cookie) =
        match action_context(state, headers, slug, &submission.csrf, path.clone()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !organization.can_admin {
        return mutation_redirect(path, "", "not-authorized", headers);
    }
    let result = if make_default {
        billing_connect::set_default_card(state, cookie, organization.id, submission.payment_method)
            .await
    } else {
        billing_connect::remove_card(state, cookie, organization.id, submission.payment_method)
            .await
    };
    match result {
        Ok(()) => mutation_redirect(
            path,
            if make_default {
                "card-default"
            } else {
                "card-removed"
            },
            "",
            headers,
        ),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&path, headers),
        Err(error) => mutation_redirect(path, "", mutation_error(&error), headers),
    }
}

/// Buys a one-time amount of credit with the saved card (#3381): back to
/// Billing once the card is charged, or on to Stripe's invoice page where the
/// bank wants the payment approved. With no card yet, the page's card form
/// buys it as it saves the card (#4750).
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
        return mutation_redirect(path, "", "not-authorized", &headers);
    }
    let Some(amount_cents) = credit_cents(&submission.choice, &submission.amount) else {
        return mutation_redirect(path, "", "invalid-credit", &headers);
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
        Err(error) => return mutation_redirect(path, "", mutation_error(&error), &headers),
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
                mutation_redirect(path, "", "invalid-redirect", &headers)
            } else {
                redirect(url, &headers)
            }
        }
        Some(AddCreditOutcome::Refused) => {
            let error = match response.refusal.as_known() {
                Some(AddCreditRefusal::InProgress) => "credit-in-progress",
                _ => credit_decline(&response.decline_code),
            };
            mutation_redirect(path, "", error, &headers)
        }
        _ => mutation_redirect(path, "", "unavailable", &headers),
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
        return mutation_redirect(path, "", "not-authorized", &headers);
    }
    let Some(amount_cents) = billing_connect::top_up_cents(&submission.amount) else {
        return mutation_redirect(path, "", "invalid-top-up", &headers);
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
        Ok(()) => mutation_redirect(path, "top-up-saved", "", &headers),
        Err(error) if error.code == ErrorCode::Unauthenticated => login_redirect(&path, &headers),
        Err(error) => mutation_redirect(path, "", mutation_error(&error), &headers),
    }
}

fn billing_path(slug: &str) -> String {
    format!("/{slug}/billing/")
}

/// The page's confirmation for a message code. The credit messages name the
/// amount, read as a number of cents and written as euros; the card messages
/// name the default card ("Visa •••• 4242"), or say "Your card" without one.
fn billing_message(value: &str, amount: &str, default_card: &str) -> String {
    let euros = amount
        .parse::<i32>()
        .ok()
        .filter(|cents| (500..=100_000).contains(cents))
        .map(|cents| format!("€{}", billing_connect::top_up_euros(cents)));
    let card = if default_card.is_empty() {
        "Your card"
    } else {
        default_card
    };
    let saved = if default_card.is_empty() {
        "Your card is saved as your default card.".to_owned()
    } else {
        format!("{card} saved as your default card.")
    };
    match (value, euros) {
        ("card-saved", _) => saved,
        ("card-topped-up", _) => {
            format!("{saved} Automatic top-up added credit; the receipt is on its way.")
        }
        ("card-top-up-pending", _) => {
            format!("{saved} Automatic top-up is charging it; your credit updates in a moment.")
        }
        ("card-top-up-declined", _) => {
            format!("{saved} Its automatic top-up was declined, so no credit was added.")
        }
        ("card-credit-added", Some(euros)) => {
            format!("{saved} {euros} added to your credit; the receipt is on its way.")
        }
        ("card-credit-added", None) => format!("{saved} Credit added."),
        ("card-default", _) => {
            format!("{card} is now your default card. Top-ups charge it from now on.")
        }
        ("card-removed", _) => "Card removed.".to_owned(),
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
/// never holds the page up. It answers with one `.cw-banner`, or with a
/// hidden placeholder whenever there is nothing to say or anything it needs
/// is unavailable; either is fetched again when the credit changes.
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
    render_template(
        StatusCode::OK,
        BillingBannerTemplate {
            banner,
            slug: &slug,
        },
    )
}

fn billing_error(value: &str) -> &'static str {
    match value {
        "not-authorized" => "You do not have permission to manage organization billing.",
        "invalid" => "The billing request was invalid.",
        "not-found" => "Billing details were not found for this organization.",
        "invalid-redirect" => "The billing provider returned an unsafe destination.",
        "card-form-off" => "Adding a card isn't available right now. Try again later.",
        "card-not-confirmed" => "Your bank didn't confirm the card. Nothing was saved.",
        "card-unfinished" => {
            "Your card is saved with Stripe, but Codewire couldn't finish adding it. Add it again to finish."
        }
        "card-setup-limit" => {
            "Too many tries at adding a card, so nothing was saved or charged. Try again later, or contact support."
        }
        "invalid-top-up" => "Enter a top-up amount from €5 to €1,000, with at most two decimals.",
        "invalid-credit" => {
            "Choose an amount, or enter one from €5 to €1,000 with at most two decimals."
        }
        "credit-in-progress" => {
            "A payment for this organization's credit is already being processed. Try again in a minute."
        }
        "credit-declined" => {
            "Your card was declined, so no credit was added. Try again, or add another card."
        }
        "credit-insufficient-funds" => {
            "Your card was declined for insufficient funds, so no credit was added."
        }
        "credit-expired-card" => "Your card has expired, so no credit was added. Add another card.",
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
        // The Stripe portal it came back from is gone (#4750).
        assert_eq!(billing_message("payment-updated", "", ""), "");
        assert_eq!(billing_message("<script>", "10000", ""), "");
        assert_eq!(
            billing_message("top-up-saved", "", ""),
            "Automatic top-up saved."
        );
        assert_eq!(
            billing_error("invalid-redirect"),
            "The billing provider returned an unsafe destination."
        );
        assert_eq!(billing_error("raw-upstream-detail"), "");
    }

    #[test]
    fn a_banks_return_loses_its_client_secret_and_keeps_the_rest() {
        let path = "/acme/billing/";
        assert_eq!(
            without_client_secret(
                path,
                Some("card_return=1&setup_intent=seti_123&setup_intent_client_secret=seti_123_secret_abc&redirect_status=succeeded")
            )
            .as_deref(),
            Some("/acme/billing/?card_return=1&setup_intent=seti_123&redirect_status=succeeded")
        );
        assert_eq!(
            without_client_secret(path, Some("setup_intent_client_secret=x")).as_deref(),
            Some(path)
        );
        for query in [
            None,
            Some(""),
            Some("message=card-saved"),
            Some("card_return=1&setup_intent=seti_123"),
        ] {
            assert_eq!(without_client_secret(path, query), None, "{query:?}");
        }
    }

    #[test]
    fn card_messages_name_the_card_and_what_saving_it_did() {
        let card = "Visa •••• 4242";
        assert_eq!(
            billing_message("card-saved", "", card),
            "Visa •••• 4242 saved as your default card."
        );
        assert_eq!(
            billing_message("card-topped-up", "", card),
            "Visa •••• 4242 saved as your default card. Automatic top-up added credit; the receipt is on its way."
        );
        assert_eq!(
            billing_message("card-credit-added", "10000", card),
            "Visa •••• 4242 saved as your default card. €100 added to your credit; the receipt is on its way."
        );
        assert_eq!(
            billing_message("card-top-up-declined", "", card),
            "Visa •••• 4242 saved as your default card. Its automatic top-up was declined, so no credit was added."
        );
        assert_eq!(
            billing_message("card-default", "", card),
            "Visa •••• 4242 is now your default card. Top-ups charge it from now on."
        );
        // Without a card to name, it says "Your card".
        assert_eq!(
            billing_message("card-saved", "", ""),
            "Your card is saved as your default card."
        );
        assert!(!billing_error("card-setup-limit").is_empty());
        assert!(!billing_error("card-form-off").is_empty());
    }

    #[test]
    fn credit_messages_name_the_amount_only_when_it_is_one() {
        assert_eq!(
            billing_message("credit-added", "10000", ""),
            "€100 added to your credit."
        );
        assert_eq!(
            billing_message("credit-added", "1250", ""),
            "€12.50 added to your credit."
        );
        assert_eq!(
            billing_message("credit-paid", "25000", ""),
            "Payment received. €250 is added to your credit in a moment."
        );
        // A missing, malformed or out-of-range amount is never echoed.
        for amount in ["", "<b>1</b>", "499", "100001", "-500", "1e4"] {
            assert_eq!(billing_message("credit-added", amount, ""), "Credit added.");
            assert_eq!(
                billing_message("credit-paid", amount, ""),
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
        // An amount typed in Other wins over a chip.
        assert_eq!(credit_cents("100", "7"), Some(700));
        assert_eq!(credit_cents("100", " "), Some(10_000));
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

    #[test]
    fn a_saved_card_whose_charge_was_declined_says_so_in_the_dialog() {
        let done = |settlement, auto_top_up_enabled, credit| billing_connect::CardSetupDone {
            settlement,
            credit,
            auto_top_up_enabled,
        };
        let credit = |outcome: AddCreditOutcome, decline_code: &str| AddCreditResponse {
            outcome: outcome.into(),
            decline_code: decline_code.into(),
            ..Default::default()
        };
        assert_eq!(
            card_declined(&done(CardSetupSettlement::OutOfCredit, true, None)),
            "Your card is saved, but its automatic top-up was declined, so no credit was added. Try another card."
        );
        assert_eq!(
            card_declined(&done(
                CardSetupSettlement::Unspecified,
                false,
                Some(credit(AddCreditOutcome::Refused, "insufficient_funds"))
            )),
            "Your card is saved, but the payment was declined for insufficient funds, so no credit was added. Try another card."
        );
        assert_eq!(
            card_declined(&done(
                CardSetupSettlement::Unspecified,
                false,
                Some(credit(AddCreditOutcome::Refused, "card_declined"))
            )),
            "Your card is saved, but the payment was declined, so no credit was added. Try another card."
        );
        // Nothing declined: the dialog closes as before.
        for nothing in [
            done(CardSetupSettlement::ToppedUp, true, None),
            done(CardSetupSettlement::Pending, true, None),
            done(CardSetupSettlement::OutOfCredit, false, None),
            done(
                CardSetupSettlement::Unspecified,
                false,
                Some(credit(AddCreditOutcome::Paid, "")),
            ),
        ] {
            assert_eq!(card_declined(&nothing), "");
        }
    }
}

#[cfg(test)]
#[path = "billing_banner_tests.rs"]
mod billing_banner_tests;
